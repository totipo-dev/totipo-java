package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

/** Small shared NIO operations; the local execution environment is trusted. */
final class NioFiles {
    private NioFiles() {}
    /** Observe spelling, not provider lookup aliases. Does not follow or inspect the child. */
    static Optional<Path> findExactDirectChild(Path parent, String expected) throws IOException {
        try (var entries = Files.newDirectoryStream(parent)) {
            return selectExactChild(entries, expected);
        } catch (DirectoryIteratorException failure) {
            throw failure.getCause();
        }
    }
    static Optional<Path> selectExactChild(Iterable<Path> entries, String expected) {
        for (Path entry : entries) {
            if (entry.getFileName().toString().equals(expected)) return Optional.of(entry);
        }
        return Optional.empty();
    }
    static Path root(Path path) throws IOException {
        if (!path.isAbsolute())
            throw new IllegalArgumentException("ABSOLUTE_PATH_REQUIRED");
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
        return Files.createTempFile(directory, prefix, ".tmp");
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
