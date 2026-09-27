package dev.totipo.format;

import static dev.totipo.format.DiscoveryFixtures.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NioDiscoveryTest {
    @TempDir Path root;

    @Test
    void safelyAbsentNamespaceIsEmptyAndReaderDoesNotCreateIt() throws Exception {
        try (var stream = Files.newDirectoryStream(root)) {
            assumeTrue(stream instanceof SecureDirectoryStream<?>);
        }
        var a = fixture(TOKEN);
        var result = run(new NioDiscoverySource(root), a.root(), DurableKnowledgeState.establishedEmpty());
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertTrue(result.observations().isEmpty());
        assertFalse(Files.exists(root.resolve("objects-v1")));
        assertEquals(0, result.knowledge().size());
    }

    @Test
    void existingNamespaceCannotBeOpenedAuthoritativelyByPathEvenWhenEmpty() throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        var result = run(new NioDiscoverySource(root), new byte[32], DurableKnowledgeState.establishedEmpty());
        assertFalse(result.resourceComplete());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertEquals(DiscoverySource.SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS, result.snapshotIssue());
        // If a platform has already safely bound the namespace, empty enumeration is complete.
        var empty = run(() -> boundSnapshot(root.resolve("objects-v1")), new byte[32], DurableKnowledgeState.establishedEmpty());
        assertTrue(empty.resourceComplete());
        assertEquals(DiscoveryState.READY, empty.discoveryState());
    }

    @Test
    void regularNamespaceFileAndSymlinkFailClosedWithoutFollowing() throws Exception {
        Path namespace = root.resolve("objects-v1");
        Files.write(namespace, new byte[1024]);
        assertUnsafePath();
        Files.delete(namespace);
        Path target = Files.createDirectory(root.resolve("target"));
        var a = fixture(TOKEN); Files.write(target.resolve(a.id().filename()), a.bytes());
        symlink(namespace, target);
        assertUnsafePath();
        // The configured root itself also cannot be silently redirected by a symlink.
        var redirected = run(new NioDiscoverySource(namespace), a.root(), DurableKnowledgeState.establishedEmpty());
        assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, redirected.snapshotIssue());
    }

    @Test
    void exactCandidatesOnlyAndNoSiblingOrNestedTraversal() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); var b = fixture(CHILD);
        Files.write(namespace.resolve(a.id().filename()), a.bytes());
        Files.write(namespace.resolve(b.id().filename()), b.bytes());
        for (String name : List.of("unrelated", "object.tmp", a.id().filename().toUpperCase(Locale.ROOT),
                "a".repeat(63), "a".repeat(65), a.id().filename() + ".sync-conflict")) {
            Files.write(namespace.resolve(name), a.bytes());
        }
        Path nested = Files.createDirectory(namespace.resolve("d".repeat(64)));
        Files.write(nested.resolve(a.id().filename()), a.bytes());
        for (String family : List.of("objects-v2", "objects-future", "objects-999")) {
            Path sibling = Files.createDirectory(root.resolve(family));
            Files.write(sibling.resolve(a.id().filename()), new byte[2000]);
        }
        Files.write(root.resolve("vault.tmp"), a.bytes());
        var snapshot = boundSnapshot(namespace);
        assertEquals(List.of(a.id().filename(), b.id().filename()).stream().sorted().toList(),
                snapshot.candidates().stream().map(c -> c.id().filename()).toList());
        var result = run(() -> snapshot, a.root(), DurableKnowledgeState.establishedEmpty());
        assertFalse(result.resourceComplete());
        assertEquals(2, result.observations().size());
        for (var o : result.observations()) {
            assertEquals(ObjectDiscovery.Classification.UNAVAILABLE, o.classification());
            assertEquals(ObjectDiscovery.Detail.UNSUPPORTED_SAFE_OPEN, o.detail());
            assertNull(o.authenticated());
        }
    }

    @Test
    void symlinkCandidatesInsideAndOutsideRootAndSiblingLinksAreNeverParsed() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN);
        Path inside = root.resolve("valid-object"); Files.write(inside, a.bytes());
        // Separate JUnit-managed directory lies outside this configured synchronization root.
        Path sync = Files.createDirectory(root.resolve("sync"));
        Path inner = Files.createDirectory(sync.resolve("objects-v1"));
        symlink(namespace.resolve(a.id().filename()), inside);
        symlink(inner.resolve(a.id().filename()), inside);
        symlink(sync.resolve("objects-v2"), namespace);
        assertTrue(boundSnapshot(namespace).candidates().isEmpty());
        var result = run(() -> boundSnapshot(inner), a.root(), DurableKnowledgeState.establishedEmpty());
        assertTrue(result.resourceComplete());
        assertEquals(0, result.knowledge().size());
    }

    @Test
    void staticUnixSocketIsNotAProtocolObjectOrSafeNamespace() throws Exception {
        // Use the short JUnit directory itself as the prebound namespace fixture;
        // Unix socket addresses have a small OS path-length limit.
        Path namespace = root;
        try (var socket = unixSocket()) {
            socket.bind(UnixDomainSocketAddress.of(namespace.resolve("a".repeat(64))));
            assertTrue(boundSnapshot(namespace).candidates().isEmpty());
        }
        Path second = Files.createDirectory(root.resolve("other-root"));
        try (var socket = unixSocket()) {
            socket.bind(UnixDomainSocketAddress.of(second.resolve("objects-v1")));
            var result = run(new NioDiscoverySource(second), new byte[32], DurableKnowledgeState.establishedEmpty());
            assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, result.snapshotIssue());
        }
    }

    @Test
    void controlledRealFilesExerciseEveryByteClassificationAndM23() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); Files.write(namespace.resolve(a.id().filename()), a.bytes());
        var one = run(controlledFiles(namespace), a.root(), DurableKnowledgeState.establishedEmpty());
        assertEquals(DiscoveryState.READY, one.discoveryState());
        assertTrue(DiscoveryTest.policy(one, one.readable().get(a.id()).tokenId()).ordinaryUse().eligible());
        var b = fixture(CHILD); Files.write(namespace.resolve(b.id().filename()), b.bytes());
        var two = run(controlledFiles(namespace), a.root(), one.knowledge());
        assertEquals(2, two.readable().evidence().size());
        assertEquals(DiscoveryState.READY, two.discoveryState());
        var future = fixture(FUTURE); Files.write(namespace.resolve(future.id().filename()), future.bytes());
        var unscoped = fixture("v1.routing.unknown-type-unscoped.001");
        Files.write(namespace.resolve(unscoped.id().filename()), unscoped.bytes());
        Files.write(namespace.resolve("b".repeat(64)), new byte[12]);
        Files.write(namespace.resolve("c".repeat(64)), new byte[200_000]);
        Files.write(namespace.resolve("d".repeat(64)), new byte[1024]);
        var result = run(controlledFiles(namespace), a.root(), two.knowledge());
        assertEquals(7, result.observations().size());
        assertEquals(4, result.knowledge().size());
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertEquals(2, result.readable().evidence().size());
        assertTrue(result.knowledge().record(unscoped.id()) instanceof OpaqueUnscopedRecord);
        assertFalse(new VaultReadiness(result.knowledge(), result.discoveryState()).authoritativeVaultReady());
        // Production source refuses the same files; fixture trust does not confer live safety.
        var refused = run(() -> boundSnapshot(namespace), a.root(), two.knowledge());
        assertTrue(refused.observations().stream().allMatch(o -> o.classification() == ObjectDiscovery.Classification.UNAVAILABLE));
    }

    @Test
    void sameSizeSameTimestampMutationIsRereadFromActualBytes() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); Path path = namespace.resolve(a.id().filename());
        Files.write(path, a.bytes()); var timestamp = Files.getLastModifiedTime(path);
        var first = run(controlledFiles(namespace), a.root(), DurableKnowledgeState.establishedEmpty());
        Files.write(path, new byte[1024]); Files.setLastModifiedTime(path, timestamp);
        var second = run(controlledFiles(namespace), a.root(), first.knowledge());
        assertEquals(ObjectDiscovery.Detail.AEAD, second.observations().get(0).detail());
        assertEquals(first.knowledge().records(), second.knowledge().records());
        assertTrue(second.readable().evidence().isEmpty());
    }

    @Test
    void controlledActualFileDisappearingAfterSnapshotIsIncomplete() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); Path path = namespace.resolve(a.id().filename()); Files.write(path, a.bytes());
        var first = run(controlledFiles(namespace), a.root(), DurableKnowledgeState.establishedEmpty());
        var source = controlledFiles(namespace);
        var result = run(() -> { var fixed = source.snapshot(); Files.delete(path); return fixed; }, a.root(), first.knowledge());
        assertFalse(result.resourceComplete());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertEquals(TokenOperationPolicy.Reason.DISCOVERY_INCOMPLETE,
                DiscoveryTest.policy(result, first.readable().get(a.id()).tokenId()).ordinaryUse().reason());
    }

    private void assertUnsafePath() {
        var result = run(new NioDiscoverySource(root), new byte[32], DurableKnowledgeState.establishedEmpty());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, result.snapshotIssue());
        assertTrue(result.observations().isEmpty());
    }

    static DiscoverySource.Snapshot boundSnapshot(Path namespace) throws IOException {
        // Test controls this directory and excludes concurrent rebinding while opening it.
        try (var stream = Files.newDirectoryStream(namespace)) {
            assumeTrue(stream instanceof SecureDirectoryStream<?>);
            return NioDiscoverySource.boundNamespace((SecureDirectoryStream<Path>) stream).snapshot();
        }
    }

    static DiscoverySource controlledFiles(Path namespace) {
        return () -> {
            var snapshot = boundSnapshot(namespace);
            var candidates = new ArrayList<DiscoverySource.Candidate>();
            for (var c : snapshot.candidates()) {
                // TEST ONLY: controlled regular fixtures, no hostile type/rebinding race.
                // This is not an implementation of §50 safe open. No production option
                // can enable these path-based candidate opens.
                candidates.add(new DiscoverySource.Candidate(c.id(), () -> Files.newByteChannel(
                        namespace.resolve(c.id().filename()), StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)));
            }
            return new DiscoverySource.Snapshot(candidates, snapshot.issue());
        };
    }

    static void symlink(Path link, Path target) throws IOException {
        try { Files.createSymbolicLink(link, target); }
        catch (UnsupportedOperationException | IOException | SecurityException e) {
            assumeTrue(false, "Symlink fixture unsupported: " + e.getClass().getSimpleName());
        }
    }

    static ServerSocketChannel unixSocket() throws IOException {
        try { return ServerSocketChannel.open(StandardProtocolFamily.UNIX); }
        catch (UnsupportedOperationException e) {
            assumeTrue(false, "Unix sockets unsupported"); throw e;
        }
    }
}
