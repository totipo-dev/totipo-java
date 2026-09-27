package dev.totipo.fs.linux;

import dev.totipo.format.DiscoverySource;
import java.io.IOException;
import java.lang.foreign.*;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(10)
class LinuxSecureSourceTest {
    @TempDir Path root;
    static final String A = "a".repeat(64), B = "b".repeat(64);
    Path family() throws IOException { return Files.createDirectory(root.resolve("objects-v1")); }
    LinuxSecureDiscoverySource source() {
        var source = new LinuxSecureDiscoverySource(root);
        assertTrue(getClass().getModule().isNativeAccessEnabled());
        assertEquals(LinuxSecureDiscoverySource.Capability.SUPPORTED, source.capability());
        return source;
    }
    static byte[] read(DiscoverySource.Snapshot snapshot) throws IOException {
        try (var channel = snapshot.candidates().getFirst().opener().open()) {
            var bytes = ByteBuffer.allocate(32);
            while (channel.read(bytes) >= 0) { /* fixtures below fit */ }
            return Arrays.copyOf(bytes.array(), bytes.position());
        }
    }
    @SuppressWarnings("restricted")
    static void fifo(Path path) throws Exception {
        var linker = Linker.nativeLinker();
        var c = linker.canonicalLayouts();
        var call = linker.downcallHandle(linker.defaultLookup().findOrThrow("mkfifo"),
                FunctionDescriptor.of(c.get("int"), c.get("void*"), c.get("int")));
        try (var arena = Arena.ofConfined()) {
            try { assertEquals(0, (int) call.invokeExact(arena.allocateFrom(path.toString()), 0600)); }
            catch (Throwable e) { throw new AssertionError(e); }
        }
    }
    @Test void pathContractAndCapabilities() throws Exception {
        for (String name : List.of("ascii", "with spaces", "caf\u00e9", "supplementary-\ud83d\udd10")) {
            Path dir = Files.createDirectory(root.resolve(name));
            try (var snapshot = new LinuxSecureDiscoverySource(dir).snapshot()) {
                assertEquals(DiscoverySource.SnapshotIssue.NONE, snapshot.issue());
            }
        }
        assertThrows(IllegalArgumentException.class, () -> new LinuxSecureDiscoverySource(Path.of("relative")));
        assertThrows(IllegalArgumentException.class, () -> LinuxLibc.utf8("\ud800"));
        assertThrows(IllegalArgumentException.class, () -> LinuxLibc.utf8("a\0b"));
        assertArrayEquals(new byte[]{97, 0}, LinuxLibc.utf8("a"));
        for (String value : List.of("a/b", ".", "..", "a\0")) {
            assertThrows(IllegalArgumentException.class, () -> LinuxSecureDiscoverySource.component(value));
        }
        assertEquals(LinuxSecureDiscoverySource.Capability.NOT_LINUX, LinuxSecureDiscoverySource.platform("Windows", "amd64"));
        assertEquals(LinuxSecureDiscoverySource.Capability.UNSUPPORTED_ARCHITECTURE, LinuxSecureDiscoverySource.platform("Linux", "aarch64"));
        Path link = root.resolve("link"); Files.createSymbolicLink(link, root);
        try (var snapshot = new LinuxSecureDiscoverySource(link).snapshot()) {
            assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, snapshot.issue());
        }
    }
    @Test void absentAndUnsafeFamilyAreDistinct() throws Exception {
        var source = source();
        try (var snapshot = source.snapshot()) { assertEquals(DiscoverySource.SnapshotIssue.NONE, snapshot.issue()); }
        Path path = root.resolve("objects-v1");
        Files.write(path, new byte[0]);
        assertUnsafe(source); Files.delete(path);
        Files.createSymbolicLink(path, root); assertUnsafe(source); Files.delete(path);
        fifo(path); assertUnsafe(source); Files.delete(path);
        try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            socket.bind(UnixDomainSocketAddress.of(path)); assertUnsafe(source);
        }
    }
    private void assertUnsafe(LinuxSecureDiscoverySource source) throws IOException {
        try (var snapshot = source.snapshot()) { assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, snapshot.issue()); }
    }
    @Test void boundNamespaceSurvivesReplacementAndLateNamesWait() throws Exception {
        Path dir = family(); Files.writeString(dir.resolve(A), "original");
        var source = source();
        try (var snapshot = source.snapshot()) {
            Files.writeString(dir.resolve(B), "late");
            assertEquals(1, snapshot.candidates().size());
            assertArrayEquals("original".getBytes(java.nio.charset.StandardCharsets.UTF_8), read(snapshot));
        }
        try (var snapshot = source.snapshot()) {
            assertEquals(2, snapshot.candidates().size());
            Files.move(dir, root.resolve("old"));
            Files.createDirectory(dir); Files.writeString(dir.resolve(A), "replacement");
            assertArrayEquals("original".getBytes(java.nio.charset.StandardCharsets.UTF_8), read(snapshot));
        }
        try (var snapshot = source.snapshot()) {
            assertEquals(1, snapshot.candidates().size());
            assertArrayEquals("replacement".getBytes(java.nio.charset.StandardCharsets.UTF_8), read(snapshot));
        }
    }
    @Test void staticTypesAndStatxLayout() throws Exception {
        Path dir = family(); var libc = new LinuxLibc();
        Files.writeString(dir.resolve(A), "regular");
        try (var fd = libc.open(dir.resolve(A).toString(), LinuxAbi.PIN)) {
            var stat = libc.stat(fd); assertTrue(stat.regular());
            assertEquals(((Number) Files.getAttribute(dir.resolve(A), "unix:ino")).longValue(), stat.inode());
        }
        Files.createDirectory(dir.resolve(B));
        try (var fd = libc.open(dir.resolve(B).toString(), LinuxAbi.PIN)) {
            assertEquals(LinuxAbi.S_IFDIR, libc.stat(fd).type());
        }
        Path outside = Files.createTempFile("totipo-outside", ".fixture");
        try {
            Files.createSymbolicLink(dir.resolve("c".repeat(64)), dir.resolve(A));
            Files.createSymbolicLink(dir.resolve("d".repeat(64)), root.resolve("elsewhere"));
            Files.writeString(root.resolve("elsewhere"), "target");
            Files.createSymbolicLink(dir.resolve("e".repeat(64)), outside);
            fifo(dir.resolve("f".repeat(64)));
            try (var link = libc.open(dir.resolve("c".repeat(64)).toString(), LinuxAbi.PIN);
                 var pipe = libc.open(dir.resolve("f".repeat(64)).toString(), LinuxAbi.PIN)) {
                assertEquals(0120000, libc.stat(link).type()); assertEquals(0010000, libc.stat(pipe).type());
            }
            // Short path avoids Unix socket's sockaddr length limit.
            try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
                Path path = root.resolve("socket"); socket.bind(UnixDomainSocketAddress.of(path));
                try (var fd = libc.open(path.toString(), LinuxAbi.PIN)) { assertEquals(0140000, libc.stat(fd).type()); }
                Files.move(path, dir.resolve("1".repeat(64)));
                Files.writeString(dir.resolve("ignored"), "ignored");
                try (var snapshot = source().snapshot()) {
                    assertEquals(List.of(A), snapshot.candidates().stream().map(c -> c.id().filename()).toList());
                }
            }
        } finally { Files.delete(outside); }
    }
    @Test void replacementBeforeReadAndDisappearanceNeverSupplyBytes() throws Exception {
        Path dir = family(); Path path = dir.resolve(A); var source = source();
        for (String type : List.of("link", "fifo", "directory", "socket", "absent")) {
            Files.writeString(path, "original");
            try (var snapshot = source.snapshot(); var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
                Files.delete(path);
                switch (type) {
                    case "link" -> Files.createSymbolicLink(path, root.resolve("target"));
                    case "fifo" -> fifo(path);
                    case "directory" -> Files.createDirectory(path);
                    case "socket" -> {
                        Path shortPath = root.resolve("socket"); socket.bind(UnixDomainSocketAddress.of(shortPath));
                        Files.move(shortPath, path);
                    }
                    default -> { }
                }
                assertThrows(IOException.class, () -> snapshot.candidates().getFirst().opener().open());
            }
            Files.deleteIfExists(path);
        }
    }
    @Test void replacementAfterPinReadsOriginalAndMismatchRejects() throws Exception {
        Path dir = family(); Path path = dir.resolve(A); Files.writeString(path, "original");
        var source = source();
        source.afterPin = () -> { Files.delete(path); Files.writeString(path, "replacement"); };
        try (var snapshot = source.snapshot()) {
            assertArrayEquals("original".getBytes(java.nio.charset.StandardCharsets.UTF_8), read(snapshot));
        }
        source.afterPin = () -> {};
        source.readableIdentity = stat -> new LinuxStatx(stat.type(), stat.inode() + 1, stat.deviceMajor(), stat.deviceMinor());
        try (var snapshot = source.snapshot()) {
            assertThrows(IOException.class, () -> snapshot.candidates().getFirst().opener().open());
        }
    }
    @Test void uncertainEnumerationIsIncomplete() throws Exception {
        Path path = family().resolve(A); Files.writeString(path, "value"); var source = source();
        source.beforeInspect = () -> Files.delete(path);
        try (var snapshot = source.snapshot()) {
            assertEquals(DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE, snapshot.issue());
        }
    }
    @Test void unavailableProbeFailsClosedAndDoesNotPoisonLaterSources() throws Exception {
        String javaHome = System.getProperty("java.home");
        try {
            // Force the read-only procfd probe fixture to be unavailable.
            System.setProperty("java.home", root.resolve("missing-runtime").toString());
            var source = new LinuxSecureDiscoverySource(root);
            assertEquals(LinuxSecureDiscoverySource.Capability.PROCFS_UNAVAILABLE, source.capability());
            try (var snapshot = source.snapshot()) {
                assertEquals(DiscoverySource.SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS, snapshot.issue());
            }
        } finally { System.setProperty("java.home", javaHome); }
        source();
    }
    @Test void permissionFailureDoesNotBecomeInvalidBytesAndReadableFdOutlivesSnapshot() throws Exception {
        Path path = family().resolve(A); Files.writeString(path, "fixture"); var source = source();
        var permissions = Files.getPosixFilePermissions(path);
        try (var snapshot = source.snapshot()) {
            Files.setPosixFilePermissions(path, java.util.Set.of());
            try { assertThrows(IOException.class, () -> snapshot.candidates().getFirst().opener().open()); }
            finally { Files.setPosixFilePermissions(path, permissions); }
        }
        var snapshot = source.snapshot();
        try (var channel = snapshot.candidates().getFirst().opener().open()) {
            snapshot.close();
            assertEquals(7, channel.read(ByteBuffer.allocate(8)));
        } finally { snapshot.close(); }
    }
    @Test void channelCopiesOnlyRemainingAndRejectsClosedReads() throws Exception {
        Path path = family().resolve(A); Files.write(path, new byte[]{1,2,3,4,5});
        for (ByteBuffer buffer : List.of(ByteBuffer.allocate(12), ByteBuffer.allocateDirect(12),
                ByteBuffer.allocate(20).position(4).limit(16).slice())) {
            for (int i = 0; i < buffer.capacity(); i++) { buffer.put(i, (byte) 99); }
            buffer.position(3).limit(7);
            try (var snapshot = source().snapshot()) {
                var channel = snapshot.candidates().getFirst().opener().open();
                try (channel) {
                    assertEquals(4, channel.read(buffer)); assertEquals(7, buffer.position());
                    assertEquals(0, channel.read(buffer));
                    buffer.clear(); assertEquals(99, buffer.get(2)); assertEquals(99, buffer.get(7));
                    assertEquals(1, buffer.get(3)); assertEquals(4, buffer.get(6));
                    buffer.position(0).limit(1); assertEquals(1, channel.read(buffer)); assertEquals(5, buffer.get(0));
                    buffer.clear(); assertEquals(-1, channel.read(buffer));
                }
                assertThrows(ClosedChannelException.class, () -> channel.read(ByteBuffer.allocate(0)));
                channel.close();
            }
        }
    }
    @Test void boundedEintrTranslationAndDescriptorStress() throws Exception {
        for (int errno : List.of(LinuxAbi.EINTR, LinuxAbi.EAGAIN, LinuxAbi.ENOENT)) {
            for (int attempt = 0; attempt < 20; attempt++) {
                assertEquals(errno == LinuxAbi.EINTR && attempt < 7, LinuxLibc.retry(errno, attempt));
            }
        }
        Path path = family().resolve(A); Files.writeString(path, "fixture"); var source = source();
        long before = descriptors();
        for (int i = 0; i < 200; i++) {
            try (var snapshot = source.snapshot()) {
                if (i % 2 == 0) { read(snapshot); }
                else {
                    Files.delete(path); fifo(path);
                    assertThrows(IOException.class, () -> snapshot.candidates().getFirst().opener().open());
                    Files.delete(path); Files.writeString(path, "fixture");
                }
            }
        }
        assertTrue(descriptors() <= before + 2);
        var snapshot = source.snapshot(); snapshot.close(); snapshot.close();
        assertThrows(ClosedChannelException.class, () -> snapshot.candidates().getFirst().opener().open());
    }
    static long descriptors() throws IOException {
        try (var files = Files.list(Path.of("/proc/self/fd"))) { return files.count(); }
    }
}
