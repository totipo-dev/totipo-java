package dev.totipo.fs.linux;

import java.io.IOException;
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Small instance-owned binding; constructing it is restricted, loading this class is not. */
final class LinuxLibc {
    private final MethodHandle open, openat, openatMode, statx, read, write, linkat, close, fsync;
    private final SymbolLookup replacementSymbols;
    private MethodHandle renameat2, unlinkat;
    static final FunctionDescriptor EXCHANGE_DESCRIPTOR = FunctionDescriptor.of(ValueLayout.JAVA_INT,
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT);
    static final FunctionDescriptor UNLINK_DESCRIPTOR = FunctionDescriptor.of(ValueLayout.JAVA_INT,
            ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT);
    private final MemoryLayout state = Linker.Option.captureStateLayout();
    private final long errnoOffset = state.byteOffset(MemoryLayout.PathElement.groupElement("errno"));
    static final int MAX_ATTEMPTS = 8;

    LinuxLibc() { this(null); }
    LinuxLibc(SymbolLookup replacementSymbols) {
        var linker = Linker.nativeLinker();
        this.replacementSymbols = replacementSymbols == null ? linker.defaultLookup() : replacementSymbols;
        var c = linker.canonicalLayouts();
        var i = c.get("int"); var p = c.get("void*");
        var l = c.get("long"); var size = c.get("size_t");
        if (!i.equals(ValueLayout.JAVA_INT) || !l.equals(ValueLayout.JAVA_LONG)
                || !size.equals(ValueLayout.JAVA_LONG) || !p.equals(ValueLayout.ADDRESS)) {
            throw new UnsupportedOperationException("UNREVIEWED_ABI");
        }
        open = bind(linker, "open", FunctionDescriptor.of(i, p, i), 2);
        openat = bind(linker, "openat", FunctionDescriptor.of(i, i, p, i), 3);
        openatMode = bind(linker, "openat", FunctionDescriptor.of(i, i, p, i, i), 3);
        statx = bind(linker, "statx", FunctionDescriptor.of(i, i, p, i, i, p), -1);
        read = bind(linker, "read", FunctionDescriptor.of(l, i, p, size), -1);
        // ssize_t write(int fd, const void *buf, size_t count): (int,address,long)->long.
        write = bind(linker, "write", FunctionDescriptor.of(l, i, p, size), -1);
        // int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags).
        linkat = bind(linker, "linkat", FunctionDescriptor.of(i, i, p, i, p, i), -1);
        close = bind(linker, "close", FunctionDescriptor.of(i, i), -1);
        fsync = bind(linker, "fsync", FunctionDescriptor.of(i, i), -1);
    }
    @SuppressWarnings("restricted")
    void prepareReplacement() throws IOException {
        if (renameat2 != null && unlinkat != null) return;
        try {
            var linker = Linker.nativeLinker();
            var capture = Linker.Option.captureCallState("errno");
            var renameSymbol = replacementSymbols.find("renameat2")
                    .orElseThrow(() -> new UnsatisfiedLinkError("renameat2"));
            var unlinkSymbol = replacementSymbols.find("unlinkat")
                    .orElseThrow(() -> new UnsatisfiedLinkError("unlinkat"));
            renameat2 = linker.downcallHandle(renameSymbol, EXCHANGE_DESCRIPTOR, capture);
            unlinkat = linker.downcallHandle(unlinkSymbol, UNLINK_DESCRIPTOR, capture);
        } catch (UnsatisfiedLinkError | UnsupportedOperationException e) {
            throw new IOException("VAULT_REPLACEMENT_UNSUPPORTED", e);
        }
    }
    @SuppressWarnings("restricted") // Reviewed descriptors; permission checked before lazy construction.
    private static MethodHandle bind(Linker linker, String name, FunctionDescriptor descriptor, int variadic) {
        var symbol = linker.defaultLookup().find(name).orElseThrow(() -> new UnsatisfiedLinkError(name));
        var capture = Linker.Option.captureCallState("errno");
        return variadic < 0 ? linker.downcallHandle(symbol, descriptor, capture)
                : linker.downcallHandle(symbol, descriptor, capture, Linker.Option.firstVariadicArg(variadic));
    }
    static byte[] utf8(String value) {
        if (value.indexOf('\0') >= 0) { throw new IllegalArgumentException("NUL_IN_PATH"); }
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(java.nio.CharBuffer.wrap(value));
            byte[] bytes = new byte[encoded.remaining() + 1]; encoded.get(bytes, 0, bytes.length - 1);
            return bytes;
        } catch (CharacterCodingException e) { throw new IllegalArgumentException("MALFORMED_PATH", e); }
    }
    static boolean retry(int errno, int attempt) { return errno == LinuxAbi.EINTR && attempt + 1 < MAX_ATTEMPTS; }
    private NativeFailure failure(MemorySegment s) { return new NativeFailure(s.get(ValueLayout.JAVA_INT, errnoOffset)); }
    static final class NativeFailure extends IOException {
        private static final long serialVersionUID = 1L;
        final int errno;
        NativeFailure(int errno) { super("NATIVE_IO_UNAVAILABLE errno=" + errno); this.errno = errno; }
    }
    private static IOException invocation(Throwable e) {
        if (e instanceof Error error) { throw error; }
        if (e instanceof RuntimeException runtime) { throw runtime; }
        return new IOException("NATIVE_INVOCATION_FAILED", e);
    }
    LinuxFd open(String path, int flags) throws IOException { return openAt(null, path, flags); }
    LinuxFd openAt(LinuxFd dir, String path, int flags) throws IOException {
        int directory = dir == null ? -1 : dir.number();
        try (var arena = Arena.ofConfined()) {
            var name = arena.allocateFrom(ValueLayout.JAVA_BYTE, utf8(path));
            var error = arena.allocate(state);
            for (int attempt = 0; ; attempt++) {
                int result;
                try { result = dir == null ? (int) open.invokeExact(error, name, flags)
                        : (int) openat.invokeExact(error, directory, name, flags); }
                catch (Throwable e) { throw invocation(e); }
                if (result >= 0) { return new LinuxFd(this, result); }
                var failure = failure(error);
                if (!retry(failure.errno, attempt)) { throw failure; }
            }
        }
    }
    LinuxStatx stat(LinuxFd fd) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var empty = arena.allocateFrom(""); var error = arena.allocate(state);
            var buffer = arena.allocate(LinuxStatx.SIZE, LinuxStatx.ALIGN);
            int result;
            try { result = (int) statx.invokeExact(error, fd.number(), empty, LinuxAbi.AT_EMPTY_PATH,
                    LinuxAbi.STATX_TYPE | LinuxAbi.STATX_INO, buffer); }
            catch (Throwable e) { throw invocation(e); }
            if (result < 0) { throw failure(error); }
            return LinuxStatx.decode(buffer);
        }
    }
    LinuxFd temporary(LinuxFd root) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var name = arena.allocateFrom("."); var error = arena.allocate(state);
            for (int attempt = 0; ; attempt++) {
                int result;
                try { result = (int) openatMode.invokeExact(error, root.number(), name,
                        LinuxAbi.O_TMPFILE | LinuxAbi.O_RDWR | LinuxAbi.O_CLOEXEC, 0600); }
                catch (Throwable e) { throw invocation(e); }
                if (result >= 0) { return new LinuxFd(this, result); }
                var failure = failure(error);
                if (!retry(failure.errno, attempt)) { throw failure; }
            }
        }
    }
    int write(LinuxFd fd, ByteBuffer src) throws IOException {
        if (!src.hasRemaining()) { return 0; }
        try (var arena = Arena.ofConfined()) {
            long count = Math.min(src.remaining(), 8192);
            var buffer = arena.allocate(count); var error = arena.allocate(state);
            buffer.asByteBuffer().put(src.slice(src.position(), (int) count));
            for (int attempt = 0; ; attempt++) {
                long result;
                try { result = (long) write.invokeExact(error, fd.number(), buffer, count); }
                catch (Throwable e) { throw invocation(e); }
                if (result >= 0 && result <= count) {
                    src.position(src.position() + (int) result); return (int) result;
                }
                if (result > count) { throw new IOException("INVALID_NATIVE_WRITE_COUNT"); }
                var failure = failure(error);
                if (!retry(failure.errno, attempt)) { throw failure; }
            }
        }
    }
    void linkInitial(LinuxFd stage, LinuxFd root) throws IOException {
        link(stage, root, "vault");
    }
    void link(LinuxFd stage, LinuxFd root, String destination) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var from = arena.allocateFrom(stage.procPath().toString());
            var to = arena.allocateFrom(destination); var error = arena.allocate(state);
            // A failed publication is not retried: its outcome may be ambiguous.
            int result;
            try { result = (int) linkat.invokeExact(error, LinuxAbi.AT_FDCWD, from,
                    root.number(), to, LinuxAbi.AT_SYMLINK_FOLLOW); }
            catch (Throwable e) { throw invocation(e); }
            if (result < 0) { throw failure(error); }
        }
    }
    void exchange(LinuxFd root, String privateName) throws IOException {
        prepareReplacement();
        try (var arena = Arena.ofConfined()) {
            var from = arena.allocateFrom(privateName); var to = arena.allocateFrom("vault");
            var error = arena.allocate(state);
            int result;
            try { result = (int) renameat2.invokeExact(error, root.number(), from,
                    root.number(), to, LinuxAbi.RENAME_EXCHANGE); }
            catch (Throwable e) { throw invocation(e); }
            if (result < 0) throw failure(error); // Never retry an exchange, including EINTR.
        }
    }
    void unlink(LinuxFd root, String privateName) throws IOException {
        prepareReplacement();
        try (var arena = Arena.ofConfined()) {
            var name = arena.allocateFrom(privateName); var error = arena.allocate(state);
            int result;
            try { result = (int) unlinkat.invokeExact(error, root.number(), name, 0); }
            catch (Throwable e) { throw invocation(e); }
            if (result < 0) throw failure(error); // No blind retry of destructive pathname operations.
        }
    }
    int read(LinuxFd fd, ByteBuffer dst) throws IOException {
        if (dst.isReadOnly()) { throw new java.nio.ReadOnlyBufferException(); }
        if (!dst.hasRemaining()) { return 0; }
        try (var arena = Arena.ofConfined()) {
            long count = Math.min(dst.remaining(), 8192);
            var buffer = arena.allocate(count); var error = arena.allocate(state);
            for (int attempt = 0; ; attempt++) {
                long result;
                try { result = (long) read.invokeExact(error, fd.number(), buffer, count); }
                catch (Throwable e) { throw invocation(e); }
                if (result == 0) { return -1; }
                if (result > 0 && result <= count) {
                    dst.put(buffer.asSlice(0, result).asByteBuffer()); return (int) result;
                }
                if (result > count) { throw new IOException("INVALID_NATIVE_READ_COUNT"); }
                var failure = failure(error);
                // EAGAIN (also EWOULDBLOCK on Linux amd64) and all other errors fail immediately.
                if (!retry(failure.errno, attempt)) { throw failure; }
            }
        }
    }
    void fsync(LinuxFd fd) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var error = arena.allocate(state);
            for (int attempt = 0; ; attempt++) {
                int result;
                try { result = (int) fsync.invokeExact(error, fd.number()); }
                catch (Throwable e) { throw invocation(e); }
                if (result == 0) { return; }
                var failure = failure(error);
                if (!retry(failure.errno, attempt)) { throw failure; }
            }
        }
    }
    void close(int fd) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var error = arena.allocate(state);
            int result;
            try { result = (int) close.invokeExact(error, fd); }
            catch (Throwable e) { throw invocation(e); }
            if (result < 0) { throw failure(error); } // Linux: never retry close, including EINTR.
        }
    }
}
