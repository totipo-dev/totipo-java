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

/** Exclusive durable journal in a pre-existing app-local directory independent of
 * synchronized storage. All processes cooperate with the lifetime advisory FileLock.
 * Existing journals cross an explicit file and directory fsync barrier before replay;
 * initialization, append and truncate force the Java channel before acknowledgement.
 * Ambiguous mutations poison the handle until reopen. Local execution is trusted.
 * Existing file modes are preserved; new journal and lock files are owner-only. */
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

    /** Narrow package-private failure seam; production operations always use real channels/fsync. */
    static class Operations {
        int write(FileChannel channel, ByteBuffer bytes, long offset) throws IOException {
            return channel.write(bytes, offset);
        }
        void force(FileChannel channel) throws IOException { channel.force(true); }
        void truncate(FileChannel channel, long offset) throws IOException { channel.truncate(offset); }
        void syncJournal(Path journal) throws IOException { LinuxDurability.fsyncFile(journal); }
        void syncDirectory(Path directory) throws IOException { LinuxDurability.fsyncDirectory(directory); }
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
        LinuxDurability.requireAvailable();
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
                storage.journal = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                operations.syncJournal(path);
                operations.syncDirectory(directory);
                storage.expectedLength = storage.journal.size();
            }
            return storage;
        } catch (IOException | RuntimeException | Error e) {
            try { storage.close(); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
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
