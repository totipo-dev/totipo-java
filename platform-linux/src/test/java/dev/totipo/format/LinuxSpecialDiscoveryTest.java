package dev.totipo.format;

import dev.totipo.storage.nio.*;

import static dev.totipo.format.NioTestFixtures.*;

import dev.totipo.storage.nio.NioDiscoverySource;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LinuxSpecialDiscoveryTest {
    @TempDir Path root;
    @Test
    void staticUnixSocketIsNotAProtocolObjectOrSafeNamespace() throws Exception {
        Path shortRoot = Files.createTempDirectory("s-");
        Path namespace = Files.createDirectory(shortRoot.resolve("objects-v1"));
        Path socketPath = namespace.resolve("a".repeat(64));
        try (var socket = unixSocket()) {
            socket.bind(UnixDomainSocketAddress.of(socketPath));
            assertTrue(new NioDiscoverySource(namespace.getParent()).snapshot().candidates().isEmpty());
        } finally { Files.deleteIfExists(socketPath); Files.delete(namespace); Files.delete(shortRoot); }
        Path second = Files.createDirectory(root.resolve("other-root"));
        try (var socket = unixSocket()) {
            socket.bind(UnixDomainSocketAddress.of(second.resolve("objects-v1")));
            var result = run(new NioDiscoverySource(second), new byte[32]);
            assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, result.snapshotIssue());
        }
    }
    static ServerSocketChannel unixSocket() throws IOException {
        try { return ServerSocketChannel.open(StandardProtocolFamily.UNIX); }
        catch (UnsupportedOperationException e) {
            assumeTrue(false, "Unix sockets unsupported"); throw e;
        }
    }
}
