package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;

/** Small shared NIO operations; the local execution environment is trusted. */
final class NioFiles {
    private NioFiles() {}
    static Path root(Path path) throws IOException {
        if (!path.isAbsolute() || path.getFileSystem() != FileSystems.getDefault())
            throw new IllegalArgumentException("ABSOLUTE_DEFAULT_FILESYSTEM_PATH_REQUIRED");
        directory(path);
        return path;
    }
    static void directory(Path path) throws IOException {
        if (!Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isDirectory())
            throw new IOException("REAL_DIRECTORY_REQUIRED");
    }
    static void regular(Path path) throws IOException {
        if (!Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isRegularFile())
            throw new IOException("REGULAR_FILE_REQUIRED");
    }
    static Path temporary(Path directory, String prefix) throws IOException {
        return Files.createTempFile(directory, prefix, ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
    }
    static byte[] read(Path path, int limit) throws IOException {
        regular(path);
        try (var in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) { return in.readNBytes(limit); }
    }
    static void cleanup(Path temp) {
        try { Files.deleteIfExists(temp); } catch (IOException | SecurityException ignored) { /* Best effort. */ }
    }
    @FunctionalInterface interface Writer { int write(FileChannel channel, ByteBuffer bytes) throws IOException; }
    static void write(FileChannel channel, byte[] bytes, Writer writer) throws IOException {
        var buffer = ByteBuffer.wrap(bytes).asReadOnlyBuffer();
        while (buffer.hasRemaining()) {
            int before = buffer.remaining();
            int count = writer.write(channel, buffer);
            if (count <= 0 || before - buffer.remaining() != count) throw new IOException("WRITE_NO_PROGRESS");
        }
    }
}
