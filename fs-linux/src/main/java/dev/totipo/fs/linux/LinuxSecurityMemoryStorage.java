package dev.totipo.fs.linux;

import dev.totipo.format.SecurityMemoryStorage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 * Exclusive durable opaque-byte storage for Linux amd64 and JDK 25 with native access.
 * The configured local security-memory directory must be app-local storage independent
 * of the synchronized vault directory. The caller supplies a pre-existing per-vault
 * directory; ancestors and local state are trusted, unlike synchronized objects-v1.
 * All Totipo processes must cooperate using this persistent advisory lock protocol.
 * This does not defend against local processes ignoring locks or replacing local state.
 *
 * <p>Requires POSIX creation attributes and a suitable local Linux filesystem/device
 * honoring force/fsync persistence semantics. No equivalent guarantee is made for
 * arbitrary NFS, remote FUSE, cloud mounts, or broken hardware write caches. There is
 * no filesystem blacklist, path-independence proof, or external anti-rollback mechanism.
 * Existing permissions are neither repaired nor rejected.
 *
 * <p>Existing journal adoption requires usable /proc/self/fd to bind the Java channel
 * to a pinned regular inode. Native Linux fsync of that verified inode, followed by
 * directory fsync, completes before replay can
 * observe them: this adopts actual restart evidence after ambiguous failures, without
 * validating, repairing, or changing it. Creation forces the file then syncs its
 * directory. Append/truncate force data and inode metadata only: the directory entry
 * is unchanged. Close is not a durability barrier. Ambiguous failures require reopen.
 */
public final class LinuxSecurityMemoryStorage implements SecurityMemoryStorage {
    static final String JOURNAL = "security-memory-v1.bin", LOCK = "security-memory.lock";
    private static final Set<Object> OWNED_DIRECTORIES = new HashSet<>();
    private final Path directory;
    private final Object identity;
    private final Operations operations;
    private FileChannel lockChannel, journal;
    private FileLock lock;
    private long expectedLength;
    private boolean closed, poisoned;
    private Snapshot reader;

    /** Narrow package-private failure seam; production operations always use real channels/libc. */
    static class Operations {
        int write(FileChannel channel, ByteBuffer bytes, long offset) throws IOException {
            return channel.write(bytes, offset);
        }
        void force(FileChannel channel) throws IOException { channel.force(true); }
        void truncate(FileChannel channel, long offset) throws IOException { channel.truncate(offset); }
        void beforeAdoptionOpen() throws IOException { }
        void syncJournal(LinuxLibc libc, LinuxFd verifiedJournal) throws IOException { libc.fsync(verifiedJournal); }
        void syncDirectory(Path directory) throws IOException {
            var libc = new LinuxLibc();
            try (var fd = libc.open(directory.toString(), LinuxAbi.DIRECTORY)) { libc.fsync(fd); }
        }
    }
    private LinuxSecurityMemoryStorage(Path directory, Object identity, Operations operations) {
        this.directory = directory; this.identity = identity; this.operations = operations;
    }
    /** Opens exclusive storage without initializing an absent journal. */
    public static LinuxSecurityMemoryStorage open(Path localStateDirectory) throws IOException {
        return open(localStateDirectory, new Operations());
    }
    static LinuxSecurityMemoryStorage open(Path directory, Operations operations) throws IOException {
        Objects.requireNonNull(directory); Objects.requireNonNull(operations);
        if (directory.getFileSystem() != FileSystems.getDefault() || !directory.isAbsolute()) {
            throw new IllegalArgumentException("ABSOLUTE_DEFAULT_FILESYSTEM_PATH_REQUIRED");
        }
        LinuxLibc.utf8(directory.toString());
        // Paths obtained from directory enumeration can contain undecodable native bytes.
        // Never let their replacement-character String designate a different native path.
        try {
            // URI path bytes use UTF-8 independently of the JVM's native path charset.
            var uri = new java.net.URI("file", "", directory.toString(), null);
            if (!directory.equals(Path.of(java.net.URI.create(uri.toASCIIString())))) {
                throw new IOException("MALFORMED_PATH");
            }
        } catch (java.net.URISyntaxException e) { throw new IOException("MALFORMED_PATH", e); }
        if (LinuxSecureDiscoverySource.platform(System.getProperty("os.name"), System.getProperty("os.arch"))
                != LinuxSecureDiscoverySource.Capability.SUPPORTED) { throw new IOException("UNSUPPORTED_PLATFORM"); }
        if (!LinuxSecurityMemoryStorage.class.getModule().isNativeAccessEnabled()) {
            throw new IOException("NATIVE_ACCESS_DISABLED");
        }
        var attrs = Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isDirectory() || attrs.isSymbolicLink()) { throw new IOException("REAL_DIRECTORY_REQUIRED"); }
        if (!Files.isReadable(directory) || !Files.isWritable(directory) || !Files.isExecutable(directory)) {
            throw new IOException("DIRECTORY_INACCESSIBLE");
        }
        if (!Files.getFileStore(directory).supportsFileAttributeView("posix")) {
            throw new IOException("POSIX_CREATION_ATTRIBUTES_REQUIRED");
        }
        Object identity = attrs.fileKey();
        if (identity == null) { throw new IOException("DIRECTORY_IDENTITY_UNAVAILABLE"); }
        // Never open a second lock channel for this directory in this JVM: closing it
        // could release process-wide POSIX locks owned by the first channel.
        synchronized (OWNED_DIRECTORIES) {
            if (!OWNED_DIRECTORIES.add(identity)) { throw new IOException("STORAGE_LOCKED"); }
        }
        var storage = new LinuxSecurityMemoryStorage(directory, identity, operations);
        try {
            // Probe exact native directory access even for absent state. No bytes are created here.
            var libc = new LinuxLibc();
            try (var fd = libc.open(directory.toString(), LinuxAbi.DIRECTORY)) {
                if (libc.stat(fd).type() != LinuxAbi.S_IFDIR) { throw new IOException("REAL_DIRECTORY_REQUIRED"); }
            }
            Path lockPath = directory.resolve(LOCK);
            if (regularOrAbsent(lockPath)) {
                storage.lockChannel = FileChannel.open(lockPath, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
            } else {
                try { storage.lockChannel = create(lockPath); }
                catch (FileAlreadyExistsException e) {
                    if (!regularOrAbsent(lockPath)) { throw e; }
                    storage.lockChannel = FileChannel.open(lockPath, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                }
            }
            try { storage.lock = storage.lockChannel.tryLock(); }
            catch (OverlappingFileLockException e) { throw new IOException("STORAGE_LOCKED", e); }
            if (storage.lock == null) { throw new IOException("STORAGE_LOCKED"); }
            Path path = directory.resolve(JOURNAL);
            if (regularOrAbsent(path)) {
                storage.adoptExisting(libc);
                operations.syncDirectory(directory);
                storage.expectedLength = storage.journal.size();
            }
            return storage;
        } catch (IOException | RuntimeException | Error e) {
            try { storage.close(); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
        }
    }
    private void adoptExisting(LinuxLibc libc) throws IOException {
        // FileChannel has no public fstat/descriptor API. Opening it through our live
        // procfd pin binds it to the exact statx identity, without racy pathname stats
        // or JDK-internal reflection. Only this kernel-owned magic link is followed.
        try (var dir = libc.open(directory.toString(), LinuxAbi.DIRECTORY);
             var pin = libc.openAt(dir, JOURNAL, LinuxAbi.PIN)) {
            var expected = libc.stat(pin);
            if (!expected.regular()) { throw new IOException("REGULAR_FILE_REQUIRED"); }
            journal = FileChannel.open(pin.procPath(), StandardOpenOption.READ, StandardOpenOption.WRITE);
            operations.beforeAdoptionOpen();
            // Recheck the fixed entry against the Java-owned inode. NONBLOCK avoids
            // hanging if a noncooperating writer replaced it with a FIFO.
            try (var fd = libc.openAt(dir, JOURNAL, LinuxAbi.O_RDONLY | LinuxAbi.O_NONBLOCK
                    | LinuxAbi.O_NOFOLLOW | LinuxAbi.O_CLOEXEC)) {
                expected.requireSame(libc.stat(fd)); // includes regular type, dev major/minor, inode
                operations.syncJournal(libc, fd);
            }
        }
    }
    private static boolean regularOrAbsent(Path path) throws IOException {
        try {
            if (!Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isRegularFile()) {
                throw new IOException("REGULAR_FILE_REQUIRED");
            }
            return true;
        } catch (NoSuchFileException e) { return false; }
    }
    private static FileChannel create(Path path) throws IOException {
        return FileChannel.open(path, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    }
    private void usable() throws IOException {
        if (closed) { throw new IOException("STORAGE_CLOSED"); }
        if (poisoned) { throw new IOException("REOPEN_REQUIRED"); }
    }
    private void mutation() throws IOException {
        usable();
        if (reader != null) { throw new IOException("READ_SNAPSHOT_ACTIVE"); }
        if (journal != null) {
            try {
                if (journal.size() != expectedLength) { throw new IOException("UNEXPECTED_JOURNAL_SIZE"); }
            } catch (IOException e) { poisoned = true; throw e; }
        }
    }
    @Override public synchronized InputStream openRead() throws IOException {
        usable();
        if (reader != null) { throw new IOException("READ_SNAPSHOT_ACTIVE"); }
        if (journal == null) { return null; }
        reader = new Snapshot(expectedLength); return reader;
    }
    @Override public synchronized void initializeDurably(byte[] header) throws IOException {
        Objects.requireNonNull(header); mutation();
        if (journal != null) { throw new IOException("JOURNAL_EXISTS"); }
        try {
            journal = create(directory.resolve(JOURNAL));
            writeFully(header, 0);
            operations.force(journal);
            operations.syncDirectory(directory);
            expectedLength = header.length;
        } catch (IOException | RuntimeException | Error e) { poisoned = true; throw e; }
    }
    @Override public synchronized void appendDurably(byte[] frame) throws IOException {
        Objects.requireNonNull(frame); mutation(); requireJournal();
        long end = Math.addExact(expectedLength, frame.length);
        try {
            writeFully(frame, expectedLength); operations.force(journal); expectedLength = end;
        } catch (IOException | RuntimeException | Error e) { poisoned = true; throw e; }
    }
    private void writeFully(byte[] bytes, long offset) throws IOException {
        var buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) {
            int position = buffer.position();
            if (operations.write(journal, buffer, offset + position) <= 0) { throw new IOException("WRITE_NO_PROGRESS"); }
        }
    }
    private void requireJournal() throws IOException {
        if (journal == null) { throw new IOException("JOURNAL_ABSENT"); }
    }
    @Override public synchronized void truncateDurably(long offset) throws IOException {
        mutation(); requireJournal();
        if (offset < 0 || offset > expectedLength) { throw new IOException("INVALID_TRUNCATION_OFFSET"); }
        try {
            operations.truncate(journal, offset); operations.force(journal); expectedLength = offset;
        } catch (IOException | RuntimeException | Error e) { poisoned = true; throw e; }
    }
    /** Invalidates reader, closes journal while locked, releases lock, closes lock channel,
     * then releases JVM ownership. Secondary I/O failures are suppressed on the first. */
    @Override public synchronized void close() throws IOException {
        if (closed) { return; }
        closed = true;
        if (reader != null) { reader.close(); }
        IOException failure = null;
        for (AutoCloseable resource : new AutoCloseable[]{journal, lock, lockChannel}) {
            if (resource == null) { continue; }
            try { resource.close(); }
            catch (Exception e) {
                var io = e instanceof IOException x ? x : new IOException("CLOSE_FAILED", e);
                if (failure == null) { failure = io; } else { failure.addSuppressed(io); }
            }
        }
        synchronized (OWNED_DIRECTORIES) { OWNED_DIRECTORIES.remove(identity); }
        if (failure != null) { throw failure; }
    }
    private final class Snapshot extends InputStream {
        private final long size;
        private long position;
        private boolean ended;
        Snapshot(long size) { this.size = size; }
        @Override public int read() throws IOException {
            byte[] one = new byte[1]; return read(one, 0, 1) < 0 ? -1 : Byte.toUnsignedInt(one[0]);
        }
        @Override public int read(byte[] bytes, int offset, int length) throws IOException {
            synchronized (LinuxSecurityMemoryStorage.this) {
                Objects.checkFromIndexSize(offset, length, bytes.length);
                usable(); if (ended) { throw new IOException("SNAPSHOT_CLOSED"); }
                if (length == 0) { return 0; }
                if (position == size) { return -1; }
                int n = journal.read(ByteBuffer.wrap(bytes, offset, (int)Math.min(length, size-position)), position);
                if (n <= 0) { poisoned = true; throw new IOException("SNAPSHOT_CHANGED_OR_UNREADABLE"); }
                position += n; return n;
            }
        }
        @Override public void close() {
            synchronized (LinuxSecurityMemoryStorage.this) {
                ended = true; if (reader == this) { reader = null; }
            }
        }
    }
}
