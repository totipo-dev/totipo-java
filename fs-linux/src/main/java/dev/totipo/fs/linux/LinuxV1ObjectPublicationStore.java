package dev.totipo.fs.linux;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable opaque v1 publication on reviewed Linux amd64/JDK 25 with native access.
 * The explicit root must preexist; its ancestors/configuration are trusted. Binds it
 * once, rejecting a final symlink. Opening does not create objects-v1. Publication
 * requires procfs, O_TMPFILE, hard links and local file/directory fsync semantics.
 * No fallback, replacement, rollback or deletion. Thread-confined; independent
 * instances use kernel no-replace exclusion, without a global lock.
 *
 * Identity and byte checks detect observed namespace/inode mutation. They do not
 * prevent an external writer from mutating the same inode, or guarantee availability
 * after the final acknowledgement check. mkdir/open are separate calls: the bound
 * directory is not necessarily the inode this process created.
 */
public final class LinuxV1ObjectPublicationStore implements V1ObjectPublicationStore {
    private static final String NAMESPACE = "objects-v1";
    private final LinuxLibc libc;
    private final LinuxFd root;
    private final Operations operations;
    private LinuxBoundFiles.Directory objects;

    /**
     * Bind the caller's existing absolute default-filesystem synchronization root.
     * @param synchronizationRoot explicit configured synchronization root
     * @return owned thread-confined store
     * @throws IOException if root safety or required capability checks fail
     */
    public static LinuxV1ObjectPublicationStore open(Path synchronizationRoot) throws IOException {
        return open(synchronizationRoot, new Operations());
    }
    static LinuxV1ObjectPublicationStore open(Path root, Operations operations) throws IOException {
        LinuxBoundFiles.path(root);
        var capability = new LinuxSecureDiscoverySource(root).capability();
        if (capability != LinuxSecureDiscoverySource.Capability.SUPPORTED) {
            throw new IOException("OBJECT_PUBLICATION_CAPABILITY_" + capability);
        }
        var libc = new LinuxLibc();
        return new LinuxV1ObjectPublicationStore(libc,
                LinuxBoundFiles.bindRoot(libc, root, LinuxAbi.DIRECTORY), operations);
    }
    private LinuxV1ObjectPublicationStore(LinuxLibc libc, LinuxFd root, Operations operations) {
        this.libc = libc; this.root = root; this.operations = operations;
    }
    /** Narrow deterministic fault/race seam. Production always executes the real fd operations. */
    static class Operations {
        void at(String point) throws IOException {}
        void mkdir(LinuxLibc libc, LinuxFd root) throws IOException { libc.mkdirAt(root, NAMESPACE, 0700); }
        LinuxFd temporary(LinuxLibc libc, LinuxFd dir) throws IOException { return libc.temporary(dir); }
        int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException { return libc.write(fd, bytes); }
        void sync(LinuxLibc libc, LinuxFd fd, String point) throws IOException { at(point); libc.fsync(fd); }
        void link(LinuxLibc libc, LinuxFd stage, LinuxFd dir, String name) throws IOException {
            at("before-link"); libc.link(stage, dir, name); at("after-link");
        }
    }
    private void bindNamespace() throws IOException {
        if (objects != null) { return; }
        LinuxBoundFiles.Directory bound;
        try { bound = LinuxBoundFiles.bindChildDirectory(libc, root, NAMESPACE); }
        catch (LinuxLibc.NativeFailure absent) {
            if (absent.errno != LinuxAbi.ENOENT) { throw absent; }
            try { operations.mkdir(libc, root); }
            catch (LinuxLibc.NativeFailure race) {
                if (race.errno != LinuxAbi.EEXIST) { throw race; }
            }
            bound = LinuxBoundFiles.bindChildDirectory(libc, root, NAMESPACE);
        }
        try {
            operations.sync(libc, bound.fd(), "namespace-sync");
            operations.sync(libc, root, "root-sync");
            objects = bound;
        } catch (IOException | RuntimeException | Error e) {
            try { bound.close(); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
        }
    }
    private void namespaceIdentity() throws IOException {
        try (var current = LinuxBoundFiles.bindChildDirectory(libc, root, NAMESPACE)) {
            objects.identity().requireSame(current.identity());
        }
    }
    private void targetIdentity(String name, LinuxStatx expected) throws IOException {
        try (var pin = libc.openAt(objects.fd(), name, LinuxAbi.PIN)) {
            expected.requireSame(libc.stat(pin));
        }
    }
    private void compare(LinuxFd pin, LinuxStatx identity, byte[] owned) throws IOException {
        try (var read = LinuxBoundFiles.reopen(libc, pin, identity, value -> value)) {
            compareRead(read, owned);
        }
    }
    private void compareRead(LinuxFd read, byte[] owned) throws IOException {
        var bytes = ByteBuffer.allocate(1025);
        while (bytes.hasRemaining()) {
            int n = libc.read(read, bytes);
            if (n == -1) { break; }
            if (n == 0) { throw new IOException("OBJECT_READ_NO_PROGRESS"); }
        }
        if (bytes.position() != 1024 || !Arrays.equals(owned, 0, 1024, bytes.array(), 0, 1024)) {
            throw new IOException("OBJECT_BYTES_MISMATCH");
        }
    }
    @Override public PublicationResult publishDurably(ObjectId id, byte[] exactObjectBytes) throws IOException {
        root.number(); Objects.requireNonNull(id); Objects.requireNonNull(exactObjectBytes);
        if (exactObjectBytes.length != 1024) { throw new IllegalArgumentException("EXACT_1024_BYTES_REQUIRED"); }
        byte[] owned = exactObjectBytes.clone();
        operations.at("snapshot");
        String name = id.filename();
        bindNamespace();
        namespaceIdentity();
        operations.at("temporary");
        try (var stage = operations.temporary(libc, objects.fd())) {
            var identity = libc.stat(stage);
            if (!identity.regular()) { throw new IOException("NOT_REGULAR"); }
            var bytes = ByteBuffer.wrap(owned).asReadOnlyBuffer();
            while (bytes.hasRemaining()) {
                int before = bytes.remaining();
                int written = operations.write(libc, stage, bytes);
                if (written <= 0 || before - bytes.remaining() != written) {
                    throw new IOException("STAGE_WRITE_NO_PROGRESS");
                }
            }
            operations.sync(libc, stage, "stage-sync");
            operations.at("stage-read");
            compare(stage, identity, owned);
            namespaceIdentity();
            try { operations.link(libc, stage, objects.fd(), name); }
            catch (LinuxLibc.NativeFailure e) {
                if (e.errno != LinuxAbi.EEXIST) { throw e; }
                return existing(name, owned);
            }
            targetIdentity(name, identity);
            operations.sync(libc, stage, "post-link-sync");
            operations.sync(libc, objects.fd(), "directory-sync");
            operations.at("final-read");
            compare(stage, identity, owned);
            targetIdentity(name, identity);
            namespaceIdentity();
            return PublicationResult.PUBLISHED_NEW;
        }
    }
    private PublicationResult existing(String name, byte[] owned) throws IOException {
        try (var pin = libc.openAt(objects.fd(), name, LinuxAbi.PIN)) {
            var identity = libc.stat(pin);
            try (var read = LinuxBoundFiles.reopen(libc, pin, identity, value -> value)) {
                operations.at("existing-pinned");
                compareRead(read, owned);
                operations.sync(libc, read, "existing-sync");
                compare(pin, identity, owned);
                operations.sync(libc, objects.fd(), "existing-directory-sync");
                targetIdentity(name, identity);
                namespaceIdentity();
                return PublicationResult.ALREADY_PRESENT_EXACT;
            }
        }
    }
    @Override public void close() throws IOException {
        try { if (objects != null) { objects.close(); } }
        finally { root.close(); }
    }
}
