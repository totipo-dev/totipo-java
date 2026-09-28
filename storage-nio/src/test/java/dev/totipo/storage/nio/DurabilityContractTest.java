package dev.totipo.storage.nio;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore.PublicationResult;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** These barriers record orchestration, not persistence. The host provider supplies link/move. */
class DurabilityContractTest {
    @TempDir Path root;
    private static final ObjectId ID = ObjectId.fromFilename("a".repeat(64));

    @Test void newPublicationSyncsCreatedParentThenContainingDirectory() throws Exception {
        var durability = new RecordingDurability();
        Path directory = root.resolve("objects-v1"), target = directory.resolve(ID.filename());
        durability.action = event -> {
            assertEquals("directory", event.operation());
            if (event.path().equals(root)) assertFalse(Files.exists(target));
            else assertArrayEquals(new byte[1024], Files.readAllBytes(target));
        };
        try (var store = NioV1ObjectPublicationStore.open(root, durability)) {
            assertEquals(PublicationResult.PUBLISHED_NEW, store.publishDurably(ID, new byte[1024]));
        }
        assertEquals(List.of(new RecordingDurability.Event("directory", root),
                new RecordingDurability.Event("directory", directory)), durability.events);
    }

    @ParameterizedTest @ValueSource(strings = {"exact", "existing", "directory", "changed", "missing"})
    void exactCallsRealInjectedCapabilityBetweenReadAndReread(String mode) throws Exception {
        Path directory = Files.createDirectory(root.resolve("objects-v1"));
        Path target = Files.write(directory.resolve(ID.filename()), new byte[1024]);
        var durability = new RecordingDurability(); durability.fail = mode;
        var sequence = new ArrayList<String>();
        durability.action = event -> {
            sequence.add(event.operation());
            assertEquals(event.operation().equals("existing") ? target : directory, event.path());
            if (event.operation().equals("directory")) {
                if (mode.equals("changed")) Files.write(target, new byte[]{1});
                if (mode.equals("missing")) Files.delete(target);
            }
        };
        var faults = new ObjectPublicationFaults(durability);
        faults.action = point -> { if (point.equals("existing-read") || point.equals("existing-reread")) sequence.add(point); };
        try (var store = faults.open(root)) {
            if (mode.equals("exact")) assertEquals(PublicationResult.ALREADY_PRESENT_EXACT, store.publishDurably(ID, new byte[1024]));
            else assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
        }
        var expected = List.of("existing-read", "existing", "directory", "existing-reread");
        assertEquals(expected.subList(0, mode.equals("existing") ? 2 : mode.equals("directory") ? 3 : 4), sequence);
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void vaultInstallationRequiresInjectedBarrierAfterCompleteBytes(boolean replacement) throws Exception {
        if (replacement) Files.write(root.resolve("vault"), new byte[87]);
        byte[] next = new byte[87]; Arrays.fill(next, (byte)42);
        var durability = new RecordingDurability(); durability.fail = "directory";
        durability.action = event -> assertArrayEquals(next, Files.readAllBytes(root.resolve("vault")));
        try (var store = NioVaultBootstrapStorage.open(root, durability)) {
            if (replacement) {
                try (var stage = store.stageReplacement(next)) { assertThrows(IOException.class, stage::replaceCanonicalDurably); }
            } else {
                try (var stage = store.stageInitial(next)) { assertThrows(IOException.class, stage::installInitialDurably); }
            }
        }
        assertEquals(List.of(new RecordingDurability.Event("directory", root)), durability.events);
        assertArrayEquals(next, Files.readAllBytes(root.resolve("vault")), "ambiguous installation is never rolled back");
    }

    @Test void failedParentCapabilityIsRetriedBeforeCreatingTemporary() throws Exception {
        var durability = new RecordingDurability(); durability.fail = "directory";
        try (var store = NioV1ObjectPublicationStore.open(root, durability)) {
            assertThrows(IOException.class, () -> store.publishDurably(ID, new byte[1024]));
            try (var entries = Files.list(root.resolve("objects-v1"))) { assertEquals(0, entries.count()); }
            durability.fail = "";
            assertEquals(PublicationResult.PUBLISHED_NEW, store.publishDurably(ID, new byte[1024]));
        }
        assertEquals(List.of(root, root, root.resolve("objects-v1")), durability.events.stream().map(RecordingDurability.Event::path).toList());
    }

    @Test void canonicalReadsAreBoundedAndNeedNoBarrier() throws Exception {
        var durability = new RecordingDurability(); durability.fail = "directory";
        try (var store = NioVaultBootstrapStorage.open(root, durability)) {
            Files.write(root.resolve("vault.tmp"), new byte[87]); assertNull(store.openCanonicalRead());
            Files.write(root.resolve("vault"), new byte[100000]);
            try (var in = store.openCanonicalRead()) { assertEquals(88, in.readAllBytes().length); }
            Files.delete(root.resolve("vault")); Files.createDirectory(root.resolve("vault"));
            assertThrows(IOException.class, store::openCanonicalRead);
        }
        assertTrue(durability.events.isEmpty());
    }

    @Test void vaultUnsupportedLinkCannotInstallCanonical() throws Exception {
        var operations = new NioVaultBootstrapStorage.Operations(new RecordingDurability()) {
            @Override void link(Path target, Path temp) { throw new UnsupportedOperationException("hard links unavailable"); }
        };
        try (var store = NioVaultBootstrapStorage.open(root, operations); var stage = store.stageInitial(new byte[87])) {
            assertThrows(UnsupportedOperationException.class, stage::installInitialDurably);
            assertNull(store.openCanonicalRead());
        }
        try (var entries = Files.list(root)) { assertEquals(0, entries.count()); }
    }

    @Test void nonDefaultProviderIsAcceptedButUnsupportedLinksFailWithoutFallback() throws Exception {
        Path archive = root.resolve("provider.zip");
        try (var fs = FileSystems.newFileSystem(java.net.URI.create("jar:" + archive.toUri()), Map.of("create", "true"))) {
            Path directory = fs.getPath("/");
            var durability = new RecordingDurability();
            try (var store = NioVaultBootstrapStorage.open(directory, durability); var stage = store.stageInitial(new byte[87])) {
                assertThrows(UnsupportedOperationException.class, stage::installInitialDurably);
                assertNull(store.openCanonicalRead());
            }
            assertTrue(durability.events.isEmpty());
        }
    }
}
