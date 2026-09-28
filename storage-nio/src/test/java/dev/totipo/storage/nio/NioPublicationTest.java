package dev.totipo.storage.nio;

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
    @TempDir Path root;
    static final ObjectId ID = ObjectId.fromFilename("a".repeat(64));
    Path target() { return root.resolve("objects-v1").resolve(ID.filename()); }
    @Test void newPublicationIsCompleteForcedExclusiveAndExistingAcknowledgesDurability() throws Exception {
        var faults = new ObjectPublicationFaults(new RecordingDurability()); faults.writeLimit = 7;
        byte[] bytes = new byte[1024]; Arrays.fill(bytes, (byte) 17);
        try (var store = faults.open(root)) {
            assertFalse(Files.exists(root.resolve("objects-v1")));
            assertEquals(PublicationResult.PUBLISHED_NEW, store.publish(ID, bytes));
            assertArrayEquals(bytes, Files.readAllBytes(target()));
            assertEquals(List.of("snapshot", "mkdir", "root-sync", "temporary", "stage-sync", "before-link", "after-link", "post-link-sync", "directory-sync"),
                    faults.events.stream().filter(e -> !e.equals("write")).toList());
            faults.events.clear();
            assertEquals(PublicationResult.ALREADY_PRESENT_EXACT, store.publish(ID, bytes));
            assertEquals(List.of("existing-read"),
                    faults.events.stream().filter(e -> e.startsWith("existing-")).toList());
            assertFalse(faults.events.contains("root-sync")); assertFalse(faults.events.contains("post-link-sync"));
            byte[] different = bytes.clone(); different[0] ^= 1;
            assertThrows(IOException.class, () -> store.publish(ID, different));
            assertArrayEquals(bytes, Files.readAllBytes(target()));
        }
        try (var names = Files.list(root.resolve("objects-v1"))) { assertEquals(List.of(ID.filename()), names.map(p -> p.getFileName().toString()).toList()); }
    }
    @ParameterizedTest @ValueSource(strings = {"exact",
            "changed", "missing", "short", "long", "directory", "same-bytes"})
    void existingAcknowledgementRequiresDurabilityAndExactPostBarrierBytes(String mode) throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        byte[] bytes = new byte[1024]; Arrays.fill(bytes, (byte)37);
        Files.write(target(), bytes);
        var faults = new ObjectPublicationFaults(new RecordingDurability()); faults.fail = mode;
        faults.action = point -> {
            if (!point.equals("existing-read")) return;
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
                assertEquals(PublicationResult.ALREADY_PRESENT_EXACT, store.publish(ID, bytes));
            else assertThrows(IOException.class, () -> store.publish(ID, bytes));
        }
        var expected = List.of("existing-read");
        int count = 1;
        assertEquals(expected.subList(0, count), faults.events.stream().filter(e -> e.startsWith("existing-")).toList());
        assertFalse(faults.events.contains("root-sync")); assertFalse(faults.events.contains("post-link-sync"));
        if (Set.of("exact", "same-bytes").contains(mode))
            assertArrayEquals(bytes, Files.readAllBytes(target()));
        if (mode.equals("changed")) assertArrayEquals(new byte[1024], Files.readAllBytes(target()));
        if (mode.equals("missing")) assertFalse(Files.exists(target()));
        try (var entries = Files.list(root.resolve("objects-v1"))) {
            assertTrue(entries.allMatch(path -> path.equals(target())), "temporary cleanup; no other authoritative names");
        }
    }
    @Test void inputSnapshotAndClosedStore() throws Exception {
        byte[] bytes = new byte[1024];
        var faults = new ObjectPublicationFaults(new RecordingDurability()); faults.action = p -> { if (p.equals("snapshot")) bytes[0] = 9; };
        var store = faults.open(root);
        assertThrows(IllegalArgumentException.class, () -> store.publish(ID, new byte[1023]));
        store.publish(ID, bytes); assertEquals(0, Files.readAllBytes(target())[0]);
        store.close(); store.close(); assertThrows(IOException.class, () -> store.publish(ID, bytes));
    }
    @ParameterizedTest @ValueSource(longs = {0, 1023, 1025, 1099511627776L})
    void exactExistingReadIsBounded(long size) throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        try (var file = new java.io.RandomAccessFile(target().toFile(), "rw")) { file.setLength(size); }
        try (var store = NioV1ObjectPublicationStore.open(root, new RecordingDurability())) {
            assertThrows(IOException.class, () -> store.publish(ID, new byte[1024]));
        }
        assertEquals(size, Files.size(target()));
    }
    @ParameterizedTest @ValueSource(strings = {"mkdir", "root-sync", "temporary", "write", "zero", "stage-sync", "before-link", "post-link-sync", "directory-sync"})
    void faultLeavesConservativeOutcomeAndNoRollback(String point) throws Exception {
        var faults = new ObjectPublicationFaults(new RecordingDurability()); faults.fail = point;
        try (var store = faults.open(root)) { assertThrows(IOException.class, () -> store.publish(ID, new byte[1024])); }
        boolean installed = Set.of("post-link-sync", "directory-sync").contains(point);
        assertEquals(installed, Files.exists(target()));
        if (installed) assertEquals(1024, Files.size(target()));
    }
    @Test void failedRootBarrierIsRetriedAndUnsupportedHardLinksHaveNoFallback() throws Exception {
        var faults = new ObjectPublicationFaults(new RecordingDurability()); faults.fail = "root-sync";
        try (var store = faults.open(root)) {
            assertThrows(IOException.class, () -> store.publish(ID, new byte[1024]));
            faults.fail = ""; store.publish(ID, new byte[1024]);
            assertEquals(2, Collections.frequency(faults.events, "root-sync"));
        }
        var unsupported = new NioV1ObjectPublicationStore.Operations(new RecordingDurability()) {
            @Override void link(Path target, Path temp) throws IOException { throw new FileSystemException(target.toString(), temp.toString(), "hard links unsupported"); }
        };
        try (var store = NioV1ObjectPublicationStore.open(root, unsupported)) {
            assertThrows(IOException.class, () -> store.publish(ObjectId.fromFilename("b".repeat(64)), new byte[1024]));
        }
        assertFalse(Files.exists(root.resolve("objects-v1").resolve("b".repeat(64))));
    }
    @ParameterizedTest @ValueSource(booleans = {true, false})
    void twoPublishersNeverOverwrite(boolean same) throws Exception {
        var barrier = new CyclicBarrier(2);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var jobs = new ArrayList<Future<PublicationResult>>();
            for (int i = 0; i < 2; i++) {
                byte[] bytes = new byte[1024]; if (!same) Arrays.fill(bytes, (byte)i);
                jobs.add(executor.submit(() -> {
                    var faults = new ObjectPublicationFaults(new RecordingDurability());
                    faults.action = p -> { if (p.equals("before-link")) try { barrier.await(10, TimeUnit.SECONDS); } catch (Exception e) { throw new IOException(e); } };
                    try (var store = faults.open(root)) { return store.publish(ID, bytes); }
                    catch (IOException collision) { return null; }
                }));
            }
            var outcomes = new ArrayList<PublicationResult>(); for (var job : jobs) outcomes.add(job.get());
            assertEquals(1, Collections.frequency(outcomes, PublicationResult.PUBLISHED_NEW));
            assertEquals(1, Collections.frequency(outcomes, same ? PublicationResult.ALREADY_PRESENT_EXACT : null));
            assertEquals(1024, Files.size(target()));
        } finally { executor.shutdownNow(); }
    }
}
