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

class NioDiscoveryTest {
    @TempDir Path root;

    @Test
    void safelyAbsentNamespaceIsEmptyAndReaderDoesNotCreateIt() throws Exception {
        var a = fixture(TOKEN);
        var result = run(new NioDiscoverySource(root), a.root());
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertTrue(result.observations().isEmpty());
        assertFalse(Files.exists(root.resolve("objects-v1")));
        assertEquals(0, result.snapshot().objects().size());
    }

    @Test void emptyNamespaceIsComplete() throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        var result = run(new NioDiscoverySource(root), new byte[32]);
        assertTrue(result.resourceComplete()); assertEquals(DiscoveryState.READY, result.discoveryState());
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
        var redirected = run(new NioDiscoverySource(namespace), a.root());
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
        var result = run(() -> snapshot, a.root());
        assertTrue(result.resourceComplete());
        assertEquals(2, result.observations().size());
        assertTrue(result.observations().stream().allMatch(o -> o.classification() == ObjectDiscovery.Classification.SUPPORTED_VALID));
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
        var result = run(() -> boundSnapshot(inner), a.root());
        assertTrue(result.resourceComplete());
        assertEquals(0, result.snapshot().objects().size());
    }

    @Test
    void controlledRealFilesExerciseEveryByteClassificationAndM23() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); Files.write(namespace.resolve(a.id().filename()), a.bytes());
        var one = run(controlledFiles(namespace), a.root());
        assertEquals(DiscoveryState.READY, one.discoveryState());
        assertTrue(policy(one, ((AcceptedToken) one.snapshot().object(a.id())).tokenId()).ordinaryUse().eligible());
        var b = fixture(CHILD); Files.write(namespace.resolve(b.id().filename()), b.bytes());
        var two = run(controlledFiles(namespace), a.root());
        assertEquals(2, two.snapshot().objects().size());
        assertEquals(DiscoveryState.READY, two.discoveryState());
        var future = fixture(FUTURE); Files.write(namespace.resolve(future.id().filename()), future.bytes());
        var unscoped = fixture("v1.routing.unknown-type-unscoped.001");
        Files.write(namespace.resolve(unscoped.id().filename()), unscoped.bytes());
        Files.write(namespace.resolve("b".repeat(64)), new byte[12]);
        Files.write(namespace.resolve("c".repeat(64)), new byte[200_000]);
        Files.write(namespace.resolve("d".repeat(64)), new byte[1024]);
        var result = run(controlledFiles(namespace), a.root());
        assertEquals(7, result.observations().size());
        assertEquals(4, result.snapshot().objects().size());
        assertTrue(result.resourceComplete());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertEquals(2, result.snapshot().objects().values().stream().filter(x -> x instanceof AcceptedToken t && t.value() != null).count());
        assertTrue(result.snapshot().object(unscoped.id()) instanceof OpaqueUnscopedRecord);
        assertTrue(result.snapshot().hasUnscopedEvidence());

    }

    @Test
    void sameSizeSameTimestampMutationIsRereadFromActualBytes() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); Path path = namespace.resolve(a.id().filename());
        Files.write(path, a.bytes()); var timestamp = Files.getLastModifiedTime(path);
        var first = run(controlledFiles(namespace), a.root());
        Files.write(path, new byte[1024]); Files.setLastModifiedTime(path, timestamp);
        var second = run(controlledFiles(namespace), a.root());
        assertEquals(ObjectDiscovery.Detail.AEAD, second.observations().get(0).detail());
        assertTrue(second.snapshot().objects().isEmpty());
        assertTrue(second.snapshot().objects().isEmpty());
    }

    @Test
    void controlledActualFileDisappearingAfterSnapshotIsIncomplete() throws Exception {
        Path namespace = Files.createDirectory(root.resolve("objects-v1"));
        var a = fixture(TOKEN); Path path = namespace.resolve(a.id().filename()); Files.write(path, a.bytes());
        var first = run(controlledFiles(namespace), a.root());
        var source = controlledFiles(namespace);
        var result = run(() -> { var fixed = source.snapshot(); Files.delete(path); return fixed; }, a.root());
        assertFalse(result.resourceComplete());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertEquals(TokenOperationPolicy.Reason.NO_CURRENT_STATE,
                policy(result, ((AcceptedToken) first.snapshot().object(a.id())).tokenId()).ordinaryUse().reason());
    }

    private void assertUnsafePath() {
        var result = run(new NioDiscoverySource(root), new byte[32]);
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, result.snapshotIssue());
        assertTrue(result.observations().isEmpty());
    }

    static DiscoverySource.Snapshot boundSnapshot(Path namespace) throws IOException {
        return new NioDiscoverySource(namespace.getParent()).snapshot();
    }
    static DiscoverySource controlledFiles(Path namespace) { return new NioDiscoverySource(namespace.getParent()); }

    static void symlink(Path link, Path target) throws IOException {
        try { Files.createSymbolicLink(link, target); }
        catch (UnsupportedOperationException | IOException | SecurityException e) {
            assumeTrue(false, "Symlink fixture unsupported: " + e.getClass().getSimpleName());
        }
    }

}
