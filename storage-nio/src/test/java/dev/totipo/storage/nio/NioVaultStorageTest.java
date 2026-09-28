package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class NioVaultStorageTest {
    @TempDir Path root;
    @Test void stagedBytesArePrivateCompleteAndNoReplacePublicationIsDurable() throws Exception {
        byte[] candidate = new byte[87]; Arrays.fill(candidate, (byte)23);
        var faults = new VaultStorageFaults(new RecordingDurability()); faults.writeLimit = 3;
        try (var store = faults.open(root); var stage = store.stageInitial(candidate)) {
            candidate[0] = 9;
            assertNull(store.openCanonicalRead());
            try (var in = stage.openRead()) { assertEquals(23, in.readAllBytes()[0]); }
            try (var names = Files.list(root)) {
                Path temp = names.findFirst().orElseThrow();
                assertTrue(temp.getFileName().toString().startsWith(".totipo-vault-"));
            }
            stage.installInitialDurably();
            assertThrows(IOException.class, stage::installInitialDurably);
            assertEquals(List.of("temporary", "stage-sync", "link", "directory-sync"), faults.events.stream().filter(e -> !e.equals("write")).toList());
            try (var collision = store.stageInitial(candidate)) { assertThrows(FileAlreadyExistsException.class, collision::installInitialDurably); }
        }
        assertEquals(23, Files.readAllBytes(root.resolve("vault"))[0]);
        try (var names = Files.list(root)) { assertEquals(List.of("vault"), names.map(p -> p.getFileName().toString()).toList()); }
    }
    @Test void stageAndDirectoryFailuresAreConservativeAndCloseCleansStages() throws Exception {
        for (String fault : List.of("temporary", "write", "zero", "partial-write", "stage-sync", "link", "directory-sync")) {
            Path directory = Files.createDirectory(root.resolve(fault));
            var faults = new VaultStorageFaults(new RecordingDurability()); faults.fail = fault;
            try (var store = faults.open(directory)) {
                assertThrows(IOException.class, () -> { try (var stage = store.stageInitial(new byte[87])) { stage.installInitialDurably(); } });
            }
            assertEquals(fault.equals("directory-sync"), Files.exists(directory.resolve("vault")));
        }
        var store = NioVaultBootstrapStorage.open(root, new RecordingDurability()); var stage = store.stageInitial(new byte[87]);
        store.close(); store.close(); assertThrows(IOException.class, stage::openRead);
    }
    @Test void atomicReplacementChecksObservedCanonicalAndDoesNotRestoreOldBytes() throws Exception {
        Files.write(root.resolve("vault"), new byte[87]);
        byte[] next = new byte[87]; Arrays.fill(next, (byte)42);
        var faults = new ReplacementStorageFaults(new RecordingDurability()); faults.fail = "directory-sync";
        try (var store = faults.open(root); var stage = store.stageReplacement(next)) {
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
            assertArrayEquals(next, Files.readAllBytes(root.resolve("vault")));
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
        }
        Files.delete(root.resolve("vault"));
        try (var store = NioVaultBootstrapStorage.open(root, new RecordingDurability()); var stage = store.stageReplacement(next)) {
            assertThrows(NoSuchFileException.class, stage::replaceCanonicalDurably);
        }
    }
    @Test void unsupportedAtomicMoveHasNoOverwriteFallback() throws Exception {
        byte[] old = new byte[87]; Files.write(root.resolve("vault"), old);
        var faults = new ReplacementStorageFaults(new RecordingDurability()); faults.unsupported = true;
        try (var store = faults.open(root); var stage = store.stageReplacement(new byte[87])) {
            assertThrows(AtomicMoveNotSupportedException.class, stage::replaceCanonicalDurably);
            assertArrayEquals(old, Files.readAllBytes(root.resolve("vault")));
        }
    }
}
