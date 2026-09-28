package dev.totipo.platform.linux;

import dev.totipo.storage.nio.*;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore.PublicationResult;
import java.io.IOException;
import java.net.*;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

class LinuxSpecialPublicationTest {
    @TempDir Path root;
    static final dev.totipo.format.ObjectId ID = dev.totipo.format.ObjectId.fromFilename("a".repeat(64));
    @Test void discoveryExcludesObservedFifoDirectoryAndSymlink() throws Exception {
        Path directory = Files.createDirectory(root.resolve("objects-v1"));
        StaticFiles.fifo(directory.resolve("a".repeat(64)));
        Files.createDirectory(directory.resolve("b".repeat(64)));
        Files.createSymbolicLink(directory.resolve("c".repeat(64)), Path.of("/dev/zero"));
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertTrue(snapshot.candidates().isEmpty());
            assertEquals(dev.totipo.format.DiscoverySource.SnapshotIssue.NONE, snapshot.issue());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"file", "directory", "symlink", "fifo", "socket"})
    void observedSpecialTargetsAreNeverOverwritten(String kind) throws Exception {
        // Short path for the Unix socket fixture.
        Path shortRoot = Files.createTempDirectory("obj-");
        Path directory = Files.createDirectory(shortRoot.resolve("objects-v1")), target = directory.resolve(ID.filename());
        try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX); var store = NioV1ObjectPublicationStore.open(shortRoot, LinuxDurability.open())) {
            switch (kind) {
                case "file" -> Files.write(target, new byte[]{1});
                case "directory" -> Files.createDirectory(target);
                case "symlink" -> Files.createSymbolicLink(target, Path.of("/dev/zero"));
                case "fifo" -> StaticFiles.fifo(target);
                case "socket" -> socket.bind(UnixDomainSocketAddress.of(target));
            }
            assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
            assertTrue(Files.exists(target, LinkOption.NOFOLLOW_LINKS));
        } finally { Files.deleteIfExists(target); Files.delete(directory); Files.delete(shortRoot); }
    }
    @ParameterizedTest @ValueSource(strings = {"file", "symlink", "fifo"})
    void observedUnsafeNamespaceFails(String kind) throws Exception {
        Path namespace = root.resolve("objects-v1");
        switch (kind) {
            case "file" -> Files.write(namespace, new byte[0]);
            case "symlink" -> Files.createSymbolicLink(namespace, root);
            case "fifo" -> StaticFiles.fifo(namespace);
        }
        try (var store = NioV1ObjectPublicationStore.open(root, LinuxDurability.open())) {
            assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
        }
    }
}
