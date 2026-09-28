package dev.totipo.fs.linux;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;

/** Linux durability only: directory metadata and adoption of previously written journals.
 * Requires native access and a local filesystem/device honoring fsync. */
final class LinuxDurability {
    private static final int O_DIRECTORY = 0200000, O_NOFOLLOW = 0400000, O_CLOEXEC = 02000000;
    private static final int EINTR = 4;
    private final MethodHandle open, fsync, close;
    private final MemoryLayout state = Linker.Option.captureStateLayout();
    private final long errnoOffset = state.byteOffset(MemoryLayout.PathElement.groupElement("errno"));

    @SuppressWarnings("restricted") // Reviewed Linux libc descriptors; access checked before construction.
    private LinuxDurability() {
        var linker = Linker.nativeLinker();
        var capture = Linker.Option.captureCallState("errno");
        open = linker.downcallHandle(linker.defaultLookup().find("open").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT),
                capture, Linker.Option.firstVariadicArg(2));
        var descriptor = FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT);
        fsync = linker.downcallHandle(linker.defaultLookup().find("fsync").orElseThrow(), descriptor, capture);
        close = linker.downcallHandle(linker.defaultLookup().find("close").orElseThrow(), descriptor, capture);
    }
    static void requireAvailable() throws IOException {
        if (!System.getProperty("os.name").equals("Linux")
                || !java.util.Set.of("amd64", "x86_64").contains(System.getProperty("os.arch")))
            throw new IOException("REVIEWED_LINUX_ABI_REQUIRED");
        if (!LinuxDurability.class.getModule().isNativeAccessEnabled()) throw new IOException("NATIVE_ACCESS_DISABLED");
    }
    static void fsyncDirectory(Path directory) throws IOException { sync(directory, O_DIRECTORY); }
    static void fsyncFile(Path file) throws IOException { sync(file, 0); }
    private static void sync(Path path, int flags) throws IOException {
        requireAvailable();
        // Linux Path's URI preserves native bytes, including non-UTF-8 names.
        byte[] name = path.toUri().getRawPath().getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        var decoded = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < name.length; i++) {
            if (name[i] == '%') {
                decoded.write(Integer.parseInt(new String(name, i + 1, 2, java.nio.charset.StandardCharsets.US_ASCII), 16));
                i += 2;
            } else decoded.write(name[i]);
        }
        decoded.write(0);
        try {
            new LinuxDurability().sync(decoded.toByteArray(), flags);
        } catch (RuntimeException | LinkageError e) { throw new IOException("DURABILITY_UNAVAILABLE", e); }
    }
    private void sync(byte[] path, int flags) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var name = arena.allocateFrom(ValueLayout.JAVA_BYTE, path);
            var error = arena.allocate(state);
            int fd = -1;
            try {
                for (int attempt = 0; ; attempt++) {
                    fd = (int) open.invokeExact(error, name, flags | O_NOFOLLOW | O_CLOEXEC);
                    if (fd >= 0) break;
                    if (error.get(ValueLayout.JAVA_INT, errnoOffset) != EINTR || attempt == 7) throw failure(error);
                }
                for (int attempt = 0; ; attempt++) {
                    int result = (int) fsync.invokeExact(error, fd);
                    if (result == 0) break;
                    if (error.get(ValueLayout.JAVA_INT, errnoOffset) != EINTR || attempt == 7) throw failure(error);
                }
            } catch (Throwable e) {
                if (fd >= 0) {
                    try { int ignored = (int) close.invokeExact(error, fd); }
                    catch (Throwable closing) { e.addSuppressed(closing); }
                    fd = -1;
                }
                if (e instanceof IOException io) throw io;
                if (e instanceof Error fatal) throw fatal;
                throw new IOException("DURABILITY_INVOCATION_FAILED", e);
            }
            // Linux close is never retried, including EINTR.
            try {
                int result = (int) close.invokeExact(error, fd);
                if (result != 0) throw failure(error);
            } catch (IOException e) { throw e; }
            catch (Throwable e) { throw new IOException("DURABILITY_CLOSE_FAILED", e); }
        }
    }
    private IOException failure(MemorySegment error) {
        return new IOException("FSYNC_IO_FAILED errno=" + error.get(ValueLayout.JAVA_INT, errnoOffset));
    }
}
