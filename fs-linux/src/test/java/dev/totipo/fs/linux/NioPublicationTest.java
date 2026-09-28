package dev.totipo.fs.linux;

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

@Timeout(30)
class NioPublicationTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path root;
    static final ObjectId ID = ObjectId.fromFilename("a".repeat(64));
    Path target() { return root.resolve("objects-v1").resolve(ID.filename()); }
    @Test void newPublicationIsCompleteForcedExclusiveAndExistingAcknowledgesDurability() throws Exception {
        var faults = new ObjectPublicationFaults(); faults.writeLimit = 7;
        byte[] bytes = new byte[1024]; Arrays.fill(bytes, (byte) 17);
        try (var store = faults.open(root)) {
            assertFalse(Files.exists(root.resolve("objects-v1")));
            assertEquals(PublicationResult.PUBLISHED_NEW, store.publishDurably(ID, bytes));
            assertArrayEquals(bytes, Files.readAllBytes(target()));
            assertEquals(List.of("snapshot", "mkdir", "root-sync", "temporary", "stage-sync", "before-link", "after-link", "post-link-sync", "directory-sync"),
                    faults.events.stream().filter(e -> !e.equals("write")).toList());
            faults.events.clear();
            assertEquals(PublicationResult.ALREADY_PRESENT_EXACT, store.publishDurably(ID, bytes));
            assertEquals(List.of("existing-read", "existing-file-sync", "existing-directory-sync", "existing-reread"),
                    faults.events.stream().filter(e -> e.startsWith("existing-")).toList());
            assertFalse(faults.events.contains("root-sync")); assertFalse(faults.events.contains("post-link-sync"));
            byte[] different = bytes.clone(); different[0] ^= 1;
            assertThrows(IOException.class, () -> store.publishDurably(ID, different));
            assertArrayEquals(bytes, Files.readAllBytes(target()));
        }
        try (var names = Files.list(root.resolve("objects-v1"))) { assertEquals(List.of(ID.filename()), names.map(p -> p.getFileName().toString()).toList()); }
    }
    @ParameterizedTest @ValueSource(strings = {"exact", "existing-file-sync", "existing-directory-sync", "existing-reread",
            "changed", "missing", "short", "long", "directory", "same-bytes"})
    void existingAcknowledgementRequiresDurabilityAndExactPostBarrierBytes(String mode) throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        byte[] bytes = new byte[1024]; Arrays.fill(bytes, (byte)37);
        Files.write(target(), bytes);
        var faults = new ObjectPublicationFaults(); faults.fail = mode;
        faults.action = point -> {
            if (!point.equals("existing-reread")) return;
            switch (mode) {
                case "changed" -> Files.write(target(), new byte[1024]);
                case "missing" -> Files.delete(target());
                case "short" -> Files.write(target(), new byte[1023]);
                case "long" -> Files.write(target(), new byte[1025]);
                case "directory" -> { Files.delete(target()); Files.createDirectory(target()); }
                case "same-bytes" -> {
                    Path replacement = Files.write(root.resolve("replacement.tmp"), bytes);
                    Files.move(replacement, target(), StandardCopyOption.REPLACE_EXISTING);
                }
            }
        };
        try (var store = faults.open(root)) {
            if (Set.of("exact", "same-bytes").contains(mode))
                assertEquals(PublicationResult.ALREADY_PRESENT_EXACT, store.publishDurably(ID, bytes));
            else assertThrows(IOException.class, () -> store.publishDurably(ID, bytes));
        }
        var expected = List.of("existing-read", "existing-file-sync", "existing-directory-sync", "existing-reread");
        int count = mode.equals("existing-file-sync") ? 2 : mode.equals("existing-directory-sync") ? 3 : 4;
        assertEquals(expected.subList(0, count), faults.events.stream().filter(e -> e.startsWith("existing-")).toList());
        assertFalse(faults.events.contains("root-sync")); assertFalse(faults.events.contains("post-link-sync"));
        if (Set.of("exact", "same-bytes", "existing-file-sync", "existing-directory-sync", "existing-reread").contains(mode))
            assertArrayEquals(bytes, Files.readAllBytes(target()));
        if (mode.equals("changed")) assertArrayEquals(new byte[1024], Files.readAllBytes(target()));
        if (mode.equals("missing")) assertFalse(Files.exists(target()));
        try (var entries = Files.list(root.resolve("objects-v1"))) {
            assertTrue(entries.allMatch(path -> path.equals(target())), "temporary cleanup; no other authoritative names");
        }
    }
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
    @Test void inputSnapshotAndClosedStore() throws Exception {
        byte[] bytes = new byte[1024];
        var faults = new ObjectPublicationFaults(); faults.action = p -> { if (p.equals("snapshot")) bytes[0] = 9; };
        var store = faults.open(root);
        assertThrows(IllegalArgumentException.class, () -> store.publishDurably(ID, new byte[1023]));
        store.publishDurably(ID, bytes); assertEquals(0, Files.readAllBytes(target())[0]);
        store.close(); store.close(); assertThrows(IOException.class, () -> store.publishDurably(ID, bytes));
    }
    @ParameterizedTest @ValueSource(strings = {"file", "directory", "symlink", "fifo", "socket"})
    void observedSpecialTargetsAreNeverOverwritten(String kind) throws Exception {
        // Short path for the Unix socket fixture.
        Path shortRoot = Files.createTempDirectory("obj-");
        Path directory = Files.createDirectory(shortRoot.resolve("objects-v1")), target = directory.resolve(ID.filename());
        try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX); var store = LinuxV1ObjectPublicationStore.open(shortRoot)) {
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
        try (var store = LinuxV1ObjectPublicationStore.open(root)) {
            assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
        }
    }
    @ParameterizedTest @ValueSource(longs = {0, 1023, 1025, 1099511627776L})
    void exactExistingReadIsBounded(long size) throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        try (var file = new java.io.RandomAccessFile(target().toFile(), "rw")) { file.setLength(size); }
        try (var store = LinuxV1ObjectPublicationStore.open(root)) {
            assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
        }
        assertEquals(size, Files.size(target()));
    }
    @ParameterizedTest @ValueSource(strings = {"mkdir", "root-sync", "temporary", "write", "zero", "stage-sync", "before-link", "post-link-sync", "directory-sync"})
    void faultLeavesConservativeOutcomeAndNoRollback(String point) throws Exception {
        var faults = new ObjectPublicationFaults(); faults.fail = point;
        try (var store = faults.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024])); }
        boolean installed = Set.of("post-link-sync", "directory-sync").contains(point);
        assertEquals(installed, Files.exists(target()));
        if (installed) assertEquals(1024, Files.size(target()));
    }
    @Test void failedRootBarrierIsRetriedAndUnsupportedHardLinksHaveNoFallback() throws Exception {
        var faults = new ObjectPublicationFaults(); faults.fail = "root-sync";
        try (var store = faults.open(root)) {
            assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
            faults.fail = ""; store.publishDurably(ID, new byte[1024]);
            assertEquals(2, Collections.frequency(faults.events, "root-sync"));
        }
        var unsupported = new LinuxV1ObjectPublicationStore.Operations() {
            @Override void link(Path target, Path temp) throws IOException { throw new FileSystemException(target.toString(), temp.toString(), "hard links unsupported"); }
        };
        try (var store = LinuxV1ObjectPublicationStore.open(root, unsupported)) {
            assertThrows(IOException.class, () -> store.publishDurably(ObjectId.fromFilename("b".repeat(64)), new byte[1024]));
        }
        assertFalse(Files.exists(root.resolve("objects-v1").resolve("b".repeat(64))));
    }
    @ParameterizedTest @ValueSource(booleans = {true, false})
    void twoPublishersNeverOverwrite(boolean same) throws Exception {
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var jobs = new ArrayList<Future<PublicationResult>>();
            for (int i = 0; i < 2; i++) {
                byte[] bytes = new byte[1024]; if (!same) Arrays.fill(bytes, (byte)i);
                jobs.add(executor.submit(() -> {
                    var faults = new ObjectPublicationFaults();
                    faults.action = p -> { if (p.equals("before-link")) try { barrier.await(10, TimeUnit.SECONDS); } catch (Exception e) { throw new IOException(e); } };
                    try (var store = faults.open(root)) { return store.publishDurably(ID, bytes); }
                    catch (IOException collision) { return null; }
                }));
            }
            var outcomes = new ArrayList<PublicationResult>(); for (var job : jobs) outcomes.add(job.get());
            assertEquals(1, Collections.frequency(outcomes, PublicationResult.PUBLISHED_NEW));
            assertEquals(1, Collections.frequency(outcomes, same ? PublicationResult.ALREADY_PRESENT_EXACT : null));
            assertEquals(1024, Files.size(target()));
        }
    }
}
