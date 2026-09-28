package dev.totipo.platform.linux;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermissions;

/** Private file-custody mechanics with mandatory owner-only temporary files. */
final class LocalPrivateFiles {
    private LocalPrivateFiles() {}
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
}
