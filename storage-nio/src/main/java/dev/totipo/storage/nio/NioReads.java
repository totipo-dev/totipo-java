package dev.totipo.storage.nio;

import dev.totipo.spi.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;

/** Fresh, bounded, no-follow storage observations. */
final class NioReads {
    private NioReads() {}
    static void expected(int expected) {
        if (expected < 0) throw new IllegalArgumentException("Invalid read bound");
    }
    static boolean directName(Path parent, String name) {
        try {
            Path child = parent.getFileSystem().getPath(name);
            return !name.isEmpty() && !name.equals(".") && !name.equals("..") && !child.isAbsolute()
                    && child.getNameCount() == 1 && child.getFileName().toString().equals(name);
        } catch (InvalidPathException invalid) { return false; }
    }
    static EntryKind kind(BasicFileAttributes attributes) {
        if (attributes.isSymbolicLink()) return EntryKind.SYMLINK;
        if (attributes.isRegularFile()) return EntryKind.REGULAR;
        if (attributes.isDirectory()) return EntryKind.DIRECTORY;
        return EntryKind.OTHER;
    }
    static StoreFailure failure(Exception failure) {
        return NioNamespace.failure(failure);
    }
    static BoundedRead child(Path parent, String name, int expected) {
        expected(expected);
        if (!directName(parent, name)) return new BoundedRead.Unavailable(StoreFailure.UNSAFE_NAMESPACE);
        try {
            NioFiles.directory(parent);
            var exact = NioFiles.findExactDirectChild(parent, name);
            if (exact.isEmpty()) return new BoundedRead.Absent();
            return exactPath(exact.get(), expected);
        } catch (IOException | SecurityException | UnsupportedOperationException failure) {
            return new BoundedRead.Unavailable(failure(failure));
        }
    }
    static BoundedRead exactPath(Path path, int expected) {
        expected(expected);
        try {
            var kind = kind(Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS));
            if (kind != EntryKind.REGULAR) return new BoundedRead.WrongKind(kind);
            // Never infer size outcomes from attributes: EOF/extra byte must actually be observed.
            byte[] bytes;
            try (var in = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
                bytes = in.readNBytes(expected);
                if (bytes.length < expected) return new BoundedRead.Undersized(bytes.length);
                if (in.read() != -1) return new BoundedRead.Oversized();
            }
            return new BoundedRead.Present(bytes);
        } catch (NoSuchFileException absent) {
            // A read race is unavailable, not evidence of exact-name absence.
            return new BoundedRead.Unavailable(StoreFailure.UNAVAILABLE);
        } catch (IOException | SecurityException | UnsupportedOperationException failure) {
            return new BoundedRead.Unavailable(failure(failure));
        }
    }
}
