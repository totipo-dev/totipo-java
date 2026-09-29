package dev.totipo.format;

import dev.totipo.storage.nio.NioDiscoverySource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Filesystem mechanics only; observations do not establish semantic state. */
class NioDiscoveryTest {
    @TempDir Path root;
    private static final String NAME = "ab".repeat(32);

    @Test void absentAndEmptyNamespacesProduceNoCandidatesAndNoWrites() throws Exception {
        var source = new NioDiscoverySource(root);
        try (var snapshot = source.snapshot()) {
            assertEquals(DiscoverySource.SnapshotIssue.NONE, snapshot.issue());
            assertTrue(snapshot.candidates().isEmpty());
        }
        assertFalse(Files.exists(root.resolve("objects-v1")));
        Files.createDirectory(root.resolve("objects-v1"));
        try (var snapshot = source.snapshot()) {
            assertEquals(DiscoverySource.SnapshotIssue.NONE, snapshot.issue());
            assertTrue(snapshot.candidates().isEmpty());
        }
    }

    @Test void rootAndNamespaceMustBeObservedDirectories() throws Exception {
        Path namespace = Files.write(root.resolve("objects-v1"), new byte[1]);
        assertUnsafe(root);
        assertUnsafe(namespace);
        Files.delete(namespace);
        Path target = Files.createDirectory(root.resolve("target"));
        Files.write(target.resolve(NAME), new byte[1024]);
        symlink(namespace, target);
        assertUnsafe(root);
        assertUnsafe(namespace);
        assertThrows(IOException.class, () -> new NioDiscoverySource(root.resolve("missing")).snapshot());
    }

    @Test void onlyDirectCanonicalRegularCandidatesAreObserved() throws Exception {
        Path directory = Files.createDirectory(root.resolve("objects-v1"));
        String second = "cd".repeat(32);
        Files.write(directory.resolve(NAME), new byte[]{1});
        Files.write(directory.resolve(second), new byte[2000]);
        for (String name : List.of("unrelated", "object.tmp", NAME.toUpperCase(Locale.ROOT),
                "a".repeat(63), "a".repeat(65), NAME + ".sync-conflict")) {
            Files.write(directory.resolve(name), new byte[1024]);
        }
        Path nested = Files.createDirectory(directory.resolve("d".repeat(64)));
        Files.write(nested.resolve(NAME), new byte[1024]);
        for (String family : List.of("objects-v2", "objects-future", "objects-999")) {
            Files.write(Files.createDirectory(root.resolve(family)).resolve(NAME), new byte[1024]);
        }
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertEquals(DiscoverySource.SnapshotIssue.NONE, snapshot.issue());
            assertEquals(List.of(NAME, second), snapshot.candidates().stream().map(c -> c.id().filename()).toList());
            try (var channel = snapshot.candidates().get(0).opener().open()) {
                assertArrayEquals(new byte[]{1}, BoundedObjectRead.read(channel));
            }
            try (var channel = snapshot.candidates().get(1).opener().open()) {
                assertEquals(1025, BoundedObjectRead.read(channel).length);
            }
        }
    }

    @Test void finalSymlinksAndSymlinkReplacementAreNotFollowed() throws Exception {
        Path directory = Files.createDirectory(root.resolve("objects-v1"));
        Path target = Files.write(root.resolve("target"), new byte[1024]);
        Path path = directory.resolve(NAME);
        symlink(path, target);
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertTrue(snapshot.candidates().isEmpty());
        }
        Files.delete(path);
        Files.write(path, new byte[1024]);
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            Files.delete(path);
            symlink(path, target);
            assertThrows(IOException.class, () -> snapshot.candidates().get(0).opener().open());
        }
    }

    @Test void openersReadCurrentBytesAndReportDisappearance() throws Exception {
        Path directory = Files.createDirectory(root.resolve("objects-v1"));
        Path path = Files.write(directory.resolve(NAME), new byte[1024]);
        var timestamp = Files.getLastModifiedTime(path);
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            byte[] changed = new byte[1024]; changed[0] = 7;
            Files.write(path, changed); Files.setLastModifiedTime(path, timestamp);
            var candidate = snapshot.candidates().get(0);
            try (var channel = candidate.opener().open()) {
                assertArrayEquals(changed, BoundedObjectRead.read(channel));
            }
            Files.delete(path);
            assertThrows(IOException.class, candidate.opener()::open);
        }
    }

    private static void assertUnsafe(Path root) throws Exception {
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertEquals(DiscoverySource.SnapshotIssue.UNSAFE_NAMESPACE, snapshot.issue());
            assertTrue(snapshot.candidates().isEmpty());
        }
    }

    private static void symlink(Path link, Path target) throws IOException {
        try { Files.createSymbolicLink(link, target); }
        catch (UnsupportedOperationException | IOException | SecurityException e) {
            assumeTrue(false, "Symlink fixture unsupported: " + e.getClass().getSimpleName());
        }
    }
}
