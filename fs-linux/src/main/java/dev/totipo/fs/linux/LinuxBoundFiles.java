package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.function.UnaryOperator;

/** Shared M2.5b path-identity and procfd checks. No pathname-based content opens. */
final class LinuxBoundFiles {
    private LinuxBoundFiles() {}
    static void path(Path root) {
        Objects.requireNonNull(root);
        if (root.getFileSystem() != java.nio.file.FileSystems.getDefault()) {
            throw new IllegalArgumentException("DEFAULT_FILESYSTEM_REQUIRED");
        }
        if (!root.isAbsolute()) { throw new IllegalArgumentException("ABSOLUTE_ROOT_REQUIRED"); }
        LinuxLibc.utf8(root.toString());
    }
    static final class UnsafeRoot extends IOException {
        private static final long serialVersionUID = 1L;
        UnsafeRoot() { super("ROOT_PATH_IDENTITY_MISMATCH"); }
    }
    static LinuxFd bindRoot(LinuxLibc libc, Path root, int flags) throws IOException {
        var fd = libc.open(root.toString(), flags);
        try {
            verifyDirectoryView(libc, fd);
            if (!Files.isSameFile(fd.procPath(), root)) { throw new UnsafeRoot(); }
            return fd;
        } catch (IOException | RuntimeException | Error e) {
            try { fd.close(); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
        }
    }
    static void verifyDirectoryView(LinuxLibc libc, LinuxFd dir) throws IOException {
        var identity = libc.stat(dir);
        if (identity.type() != LinuxAbi.S_IFDIR) { throw new IOException("NOT_DIRECTORY"); }
        try (var view = libc.open(dir.procPath().toString(),
                LinuxAbi.O_RDONLY | LinuxAbi.O_DIRECTORY | LinuxAbi.O_CLOEXEC)) {
            identity.requireSame(libc.stat(view));
        }
    }
    /** Pins one exact child; never follows its final component. Caller owns the result. */
    static Directory bindChildDirectory(LinuxLibc libc, LinuxFd parent, String child) throws IOException {
        if (child.isEmpty() || child.equals(".") || child.equals("..") || child.indexOf('/') >= 0) {
            throw new IllegalArgumentException("EXACT_CHILD_REQUIRED");
        }
        var fd = libc.openAt(parent, child, LinuxAbi.DIRECTORY);
        try {
            var identity = libc.stat(fd);
            if (identity.type() != LinuxAbi.S_IFDIR) { throw new IOException("NOT_DIRECTORY"); }
            return new Directory(fd, identity);
        } catch (IOException | RuntimeException | Error e) {
            try { fd.close(); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
        }
    }
    record Directory(LinuxFd fd, LinuxStatx identity) implements AutoCloseable {
        @Override public void close() throws IOException { fd.close(); }
    }
    static LinuxFd reopen(LinuxLibc libc, LinuxFd pin, LinuxStatx identity,
                          UnaryOperator<LinuxStatx> inspected) throws IOException {
        if (!identity.regular()) { throw new IOException("NOT_REGULAR"); }
        var readable = libc.open(pin.procPath().toString(),
                LinuxAbi.O_RDONLY | LinuxAbi.O_NONBLOCK | LinuxAbi.O_CLOEXEC);
        try {
            identity.requireSame(inspected.apply(libc.stat(readable)));
            return readable;
        } catch (IOException | RuntimeException | Error e) {
            try { readable.close(); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
        }
    }
}
