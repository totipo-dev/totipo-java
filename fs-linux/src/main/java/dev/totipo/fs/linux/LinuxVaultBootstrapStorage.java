package dev.totipo.fs.linux;

import dev.totipo.format.VaultBootstrapReplacementStorage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * Canonical-only VAULT publication and replacement on Linux amd64/JDK 25 with native access.
 * The explicit root must preexist; its ancestors/configuration are trusted. Binds
 * that directory once, rejecting a final symlink and checking Java/native identity.
 * Requires usable procfs, O_TMPFILE, hard links and file/directory fsync with local
 * filesystem durability semantics. No named-temp or publication fallback exists.
 * Thread-confined. Reads own independent descriptors and must be closed by callers;
 * closing storage invalidates all stages and closes the bound directory.
 * Replacement additionally requires libc/filesystem RENAME_EXCHANGE. Private
 * replacement residue is nonauthoritative but may expose historical password verifiers.
 * Cleanup checks identity before unlink; these are separate syscalls, not an atomic
 * conditional unlink against an uncooperative namespace mutator.
 * Does not provide freshness or availability guarantees.
 */
public final class LinuxVaultBootstrapStorage implements VaultBootstrapReplacementStorage {
    private final LinuxLibc libc;
    private final LinuxFd root;
    private final Operations operations;
    private final Set<Stage> stages = new HashSet<>();
    static final String REPLACEMENT_PREFIX = ".totipo-vault-rewrap-";
    static final int NAME_ATTEMPTS = 16;

    /** Open the caller's existing absolute default-filesystem root, without creating it.
     * @param configuredRoot synchronized root
     * @return owned thread-confined storage
     * @throws IOException if capability, root safety or access checks fail
     */
    public static LinuxVaultBootstrapStorage open(Path configuredRoot) throws IOException {
        return open(configuredRoot, new Operations());
    }
    static LinuxVaultBootstrapStorage open(Path configuredRoot, Operations operations) throws IOException {
        LinuxBoundFiles.path(configuredRoot);
        var capability = new LinuxSecureDiscoverySource(configuredRoot).capability();
        if (capability != LinuxSecureDiscoverySource.Capability.SUPPORTED) {
            throw new IOException("VAULT_STORAGE_CAPABILITY_" + capability);
        }
        var libc = operations.libc();
        return new LinuxVaultBootstrapStorage(libc,
                LinuxBoundFiles.bindRoot(libc, configuredRoot, LinuxAbi.DIRECTORY), operations);
    }
    private LinuxVaultBootstrapStorage(LinuxLibc libc, LinuxFd root, Operations operations) {
        this.libc = libc; this.root = root; this.operations = operations;
    }
    /** Narrow package-private fault seam; the production path always uses real fd operations. */
    static class Operations {
        LinuxLibc libc() { return new LinuxLibc(); }
        LinuxFd temporary(LinuxLibc libc, LinuxFd root) throws IOException { return libc.temporary(root); }
        int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException { return libc.write(fd, bytes); }
        void syncStage(LinuxLibc libc, LinuxFd fd) throws IOException { libc.fsync(fd); }
        void link(LinuxLibc libc, LinuxFd stage, LinuxFd root) throws IOException { libc.linkInitial(stage, root); }
        void syncDirectory(LinuxLibc libc, LinuxFd root) throws IOException { libc.fsync(root); }
        String replacementName() {
            byte[] random = new byte[16]; NameRandom.INSTANCE.nextBytes(random);
            char[] hex = new char[32];
            for (int i = 0; i < random.length; i++) {
                hex[2 * i] = "0123456789abcdef".charAt((random[i] & 255) >>> 4);
                hex[2 * i + 1] = "0123456789abcdef".charAt(random[i] & 15);
            }
            return REPLACEMENT_PREFIX + new String(hex) + ".tmp";
        }
        void linkReplacement(LinuxLibc libc, LinuxFd stage, LinuxFd root, String name) throws IOException {
            libc.link(stage, root, name);
        }
        void exchange(LinuxLibc libc, LinuxFd root, String name) throws IOException { libc.exchange(root, name); }
        void unlink(LinuxLibc libc, LinuxFd root, String name) throws IOException { libc.unlink(root, name); }
    }
    private static final class NameRandom { private static final SecureRandom INSTANCE = new SecureRandom(); }
    private InputStream read(LinuxFd pin) throws IOException {
        var readable = LinuxBoundFiles.reopen(libc, pin, libc.stat(pin), value -> value);
        return Channels.newInputStream(new LinuxReadChannel(libc, readable));
    }
    @Override public InputStream openCanonicalRead() throws IOException {
        root.number();
        LinuxFd pin;
        try { pin = libc.openAt(root, "vault", LinuxAbi.PIN); }
        catch (LinuxLibc.NativeFailure e) {
            if (e.errno == LinuxAbi.ENOENT) { return null; }
            throw e;
        }
        InputStream readable = null;
        try {
            try (pin) { readable = read(pin); }
            var result = readable; readable = null; return result;
        } finally {
            if (readable != null) { readable.close(); }
        }
    }
    @Override public StagedBootstrap stageInitial(byte[] exactCandidate) throws IOException {
        return stage(exactCandidate, InitialStage::new);
    }
    @Override public StagedReplacement stageReplacement(byte[] exactCandidate) throws IOException {
        return stage(exactCandidate, ReplacementStage::new);
    }
    private <T extends Stage> T stage(byte[] exactCandidate, Function<LinuxFd, T> factory) throws IOException {
        root.number(); Objects.requireNonNull(exactCandidate);
        byte[] owned = exactCandidate.clone();
        try {
            var fd = operations.temporary(libc, root);
            try {
                if (!libc.stat(fd).regular()) { throw new IOException("NOT_REGULAR"); }
                var bytes = ByteBuffer.wrap(owned).asReadOnlyBuffer();
                while (bytes.hasRemaining()) {
                    int before = bytes.remaining();
                    int written = operations.write(libc, fd, bytes);
                    if (written <= 0 || before - bytes.remaining() != written) {
                        throw new IOException("STAGE_WRITE_NO_PROGRESS");
                    }
                }
                operations.syncStage(libc, fd);
                var stage = factory.apply(fd); stages.add(stage); return stage;
            } catch (IOException | RuntimeException | Error e) {
                try { fd.close(); } catch (IOException close) { e.addSuppressed(close); }
                throw e;
            }
        } finally {
            Arrays.fill(owned, (byte) 0); // Best effort, not secure JVM erasure.
        }
    }
    private abstract class Stage implements AutoCloseable {
        final LinuxFd fd;
        boolean attempted;
        Stage(LinuxFd fd) { this.fd = fd; }
        public InputStream openRead() throws IOException { root.number(); fd.number(); return read(fd); }
        @Override public void close() throws IOException { stages.remove(this); fd.close(); }
    }
    private final class InitialStage extends Stage implements StagedBootstrap {
        InitialStage(LinuxFd fd) { super(fd); }
        @Override public void installInitialDurably() throws IOException {
            root.number(); fd.number();
            if (attempted) { throw new IOException("INSTALL_ALREADY_ATTEMPTED"); }
            attempted = true; // Includes EEXIST and ambiguous failures; never retry or roll back.
            operations.link(libc, fd, root);
            operations.syncStage(libc, fd); // Conservative post-link inode metadata barrier.
            operations.syncDirectory(libc, root);
        }
    }
    private LinuxStatx regularIdentity(LinuxFd pin) throws IOException {
        var identity = libc.stat(pin);
        if (!identity.regular()) throw new IOException("NOT_REGULAR");
        return identity;
    }
    private void requireIdentity(String name, LinuxStatx expected) throws IOException {
        try (var pin = libc.openAt(root, name, LinuxAbi.PIN)) {
            expected.requireSame(regularIdentity(pin));
        }
    }
    private final class ReplacementStage extends Stage implements StagedReplacement {
        private String privateName;
        private LinuxStatx cleanupIdentity;
        // Retained until close, including cleanup retry, so an old inode number cannot be reused.
        private LinuxFd oldPin;
        private boolean closed;
        ReplacementStage(LinuxFd fd) { super(fd); }

        private void materialize(LinuxStatx stageIdentity) throws IOException {
            for (int attempt = 0; attempt < NAME_ATTEMPTS; attempt++) {
                String name = operations.replacementName();
                if (!name.matches("\\.totipo-vault-rewrap-[0-9a-f]{32}\\.tmp")) {
                    throw new IOException("INVALID_REPLACEMENT_NAME");
                }
                try { operations.linkReplacement(libc, fd, root, name); }
                catch (LinuxLibc.NativeFailure e) {
                    if (e.errno == LinuxAbi.EEXIST) continue;
                    throw e;
                }
                privateName = name; cleanupIdentity = stageIdentity;
                requireIdentity(name, stageIdentity);
                return;
            }
            throw new IOException("REPLACEMENT_NAME_COLLISIONS_EXHAUSTED");
        }
        @Override public void replaceCanonicalDurably() throws IOException {
            root.number(); fd.number();
            if (attempted) throw new IOException("REPLACEMENT_ALREADY_ATTEMPTED");
            attempted = true; // Terminal even if capability/link/precheck/exchange fails.
            libc.prepareReplacement(); // Lazy: missing replacement symbols do not poison initial creation.
            var stageIdentity = regularIdentity(fd);
            materialize(stageIdentity);
            oldPin = libc.openAt(root, "vault", LinuxAbi.PIN);
            var oldIdentity = regularIdentity(oldPin);
            operations.exchange(libc, root, privateName); // Single attempt, both paths relative to bound root.
            cleanupIdentity = null; // Successful syscall is not proof of what was displaced.
            try {
                requireIdentity("vault", stageIdentity);
                requireIdentity(privateName, oldIdentity);
            } catch (IOException e) {
                // Preserve actual evidence. Never exchange back or delete uncertain private entries.
                try { operations.syncStage(libc, fd); } catch (IOException barrier) { e.addSuppressed(barrier); }
                try { operations.syncDirectory(libc, root); } catch (IOException barrier) { e.addSuppressed(barrier); }
                throw e;
            }
            cleanupIdentity = oldIdentity;
            operations.syncStage(libc, fd);
            cleanup();
            operations.syncDirectory(libc, root);
        }
        private void cleanup() {
            if (privateName == null || cleanupIdentity == null) return;
            try (var pin = libc.openAt(root, privateName, LinuxAbi.PIN)) {
                cleanupIdentity.requireSame(regularIdentity(pin));
                // Best effort only: Linux has no inode-conditional unlinkat. Namespace mutation
                // between this check and unlink can substitute the entry (documented boundary).
                operations.unlink(libc, root, privateName);
                privateName = null;
            } catch (LinuxLibc.NativeFailure e) {
                if (e.errno == LinuxAbi.ENOENT) privateName = null;
            } catch (IOException e) { /* Non-gating residue; close may recheck and retry. */ }
        }
        @Override public void close() throws IOException {
            if (closed) return;
            closed = true;
            try { cleanup(); }
            finally {
                try { if (oldPin != null) oldPin.close(); }
                finally { super.close(); }
            }
        }
    }
    @Override public void close() throws IOException {
        IOException failure = null;
        for (var stage : Set.copyOf(stages)) {
            try { stage.close(); }
            catch (IOException e) { if (failure == null) { failure = e; } else { failure.addSuppressed(e); } }
        }
        try { root.close(); }
        catch (IOException e) { if (failure == null) { failure = e; } else { failure.addSuppressed(e); } }
        if (failure != null) { throw failure; }
    }
}
