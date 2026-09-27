package dev.totipo.fs.linux;

import dev.totipo.format.VaultBootstrapStorage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Canonical-only initial VAULT storage on Linux amd64/JDK 25 with native access.
 * The explicit root must preexist; its ancestors/configuration are trusted. Binds
 * that directory once, rejecting a final symlink and checking Java/native identity.
 * Requires usable procfs, O_TMPFILE, hard links and file/directory fsync with local
 * filesystem durability semantics. No named-temp or publication fallback exists.
 * Thread-confined. Reads own independent descriptors and must be closed by callers;
 * closing storage invalidates all stages and closes the bound directory.
 * Does not provide password replacement, freshness, or availability guarantees.
 */
public final class LinuxVaultBootstrapStorage implements VaultBootstrapStorage {
    private final LinuxLibc libc;
    private final LinuxFd root;
    private final Operations operations;
    private final Set<Stage> stages = new HashSet<>();

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
        var libc = new LinuxLibc();
        return new LinuxVaultBootstrapStorage(libc,
                LinuxBoundFiles.bindRoot(libc, configuredRoot, LinuxAbi.DIRECTORY), operations);
    }
    private LinuxVaultBootstrapStorage(LinuxLibc libc, LinuxFd root, Operations operations) {
        this.libc = libc; this.root = root; this.operations = operations;
    }
    /** Narrow package-private fault seam; the production path always uses real fd operations. */
    static class Operations {
        LinuxFd temporary(LinuxLibc libc, LinuxFd root) throws IOException { return libc.temporary(root); }
        int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException { return libc.write(fd, bytes); }
        void syncStage(LinuxLibc libc, LinuxFd fd) throws IOException { libc.fsync(fd); }
        void link(LinuxLibc libc, LinuxFd stage, LinuxFd root) throws IOException { libc.linkInitial(stage, root); }
        void syncDirectory(LinuxLibc libc, LinuxFd root) throws IOException { libc.fsync(root); }
    }
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
                var stage = new Stage(fd); stages.add(stage); return stage;
            } catch (IOException | RuntimeException | Error e) {
                try { fd.close(); } catch (IOException close) { e.addSuppressed(close); }
                throw e;
            }
        } finally {
            Arrays.fill(owned, (byte) 0); // Best effort, not secure JVM erasure.
        }
    }
    private final class Stage implements StagedBootstrap {
        private final LinuxFd fd;
        private boolean attempted;
        Stage(LinuxFd fd) { this.fd = fd; }
        @Override public InputStream openRead() throws IOException { root.number(); fd.number(); return read(fd); }
        @Override public void installInitialDurably() throws IOException {
            root.number(); fd.number();
            if (attempted) { throw new IOException("INSTALL_ALREADY_ATTEMPTED"); }
            attempted = true; // Includes EEXIST and ambiguous failures; never retry or roll back.
            operations.link(libc, fd, root);
            operations.syncStage(libc, fd); // Conservative post-link inode metadata barrier.
            operations.syncDirectory(libc, root);
        }
        @Override public void close() throws IOException { stages.remove(this); fd.close(); }
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
