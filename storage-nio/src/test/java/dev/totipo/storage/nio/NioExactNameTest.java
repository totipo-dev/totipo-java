package dev.totipo.storage.nio;

import dev.totipo.format.ObjectId;
import java.io.IOException;
import java.nio.file.*;
import java.util.List;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static dev.totipo.format.V1ObjectPublicationStore.PublicationResult.*;
import static org.junit.jupiter.api.Assertions.*;

class NioExactNameTest {
    @TempDir Path root;
    private static final String NAME = "abcdef01".repeat(8);

    @ParameterizedTest @ValueSource(strings = {"vault", "objects-v1",
            "abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01abcdef01"})
    void selectionUsesObservedSpellingIndependentOfHostLookup(String expected) {
        Path upper = Path.of(expected.toUpperCase(Locale.ROOT));
        Path mixed = Path.of("" + Character.toUpperCase(expected.charAt(0)) + expected.substring(1));
        Path exact = Path.of(expected);
        assertTrue(NioFiles.selectExactChild(List.of(upper, mixed), expected).isEmpty());
        assertSame(exact, NioFiles.selectExactChild(List.of(upper, exact, mixed), expected).orElseThrow());
    }

    @Test void enumerationIsDirectDoesNotFollowChildAndErrorsAreNotAbsence() throws Exception {
        Path nested = Files.createDirectory(root.resolve("nested"));
        Files.write(nested.resolve("vault"), new byte[]{1});
        assertTrue(NioFiles.findExactDirectChild(root, "vault").isEmpty());
        Path link = Files.createSymbolicLink(root.resolve("vault"), root.resolve("missing"));
        assertEquals(link, NioFiles.findExactDirectChild(root, "vault").orElseThrow());
        assertThrows(IOException.class, () -> NioFiles.findExactDirectChild(root.resolve("missing"), "vault"));
    }

    @Test void uppercaseVaultIsAbsentAndNeverReplacedOrMutated() throws Exception {
        byte[] old = {7, 8, 9};
        Path upper = Files.write(root.resolve("VAULT"), old);
        var modified = Files.getLastModifiedTime(upper);
        try (var store = NioVaultBootstrapStorage.open(root, new RecordingDurability())) {
            assertNull(store.openCanonicalRead());
            try (var replacement = store.stageReplacement(new byte[87])) {
                assertThrows(NoSuchFileException.class, replacement::replaceCanonicalDurably);
            }
            try (var initial = store.stageInitial(new byte[87])) { initial.installInitialDurably(); }
            assertEquals("vault", NioFiles.findExactDirectChild(root, "vault").orElseThrow().getFileName().toString());
            try (var in = store.openCanonicalRead()) { assertArrayEquals(new byte[87], in.readAllBytes()); }
        }
        assertArrayEquals(old, Files.readAllBytes(upper));
        assertEquals(modified, Files.getLastModifiedTime(upper));
    }

    @Test void uppercaseNamespaceIsIgnoredAndLazyPublicationCreatesExactSibling() throws Exception {
        Path upper = Files.createDirectory(root.resolve("OBJECTS-V1"));
        byte[] bytes = new byte[1024];
        Path ignored = Files.write(upper.resolve(NAME), bytes);
        var modified = Files.getLastModifiedTime(ignored);
        try (var snapshot = new NioDiscoverySource(root).snapshot()) { assertTrue(snapshot.candidates().isEmpty()); }
        try (var store = NioV1ObjectPublicationStore.open(root, new RecordingDurability())) {
            assertTrue(NioFiles.findExactDirectChild(root, "objects-v1").isEmpty());
            assertEquals(PUBLISHED_NEW, store.publish(ObjectId.fromFilename(NAME), bytes));
        }
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertEquals(List.of(NAME), snapshot.candidates().stream().map(c -> c.id().filename()).toList());
        }
        assertArrayEquals(bytes, Files.readAllBytes(ignored));
        assertEquals(modified, Files.getLastModifiedTime(ignored));
        try (var entries = Files.list(upper)) { assertEquals(List.of(ignored), entries.toList()); }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void namespaceCollisionRequiresExactlySpelledWinner(boolean exactWinner) throws Exception {
        Path upper = Files.createDirectory(root.resolve("OBJECTS-V1"));
        Path ignored = Files.write(upper.resolve(NAME), new byte[1024]);
        var modified = Files.getLastModifiedTime(ignored);
        var operations = new NioV1ObjectPublicationStore.Operations(new RecordingDurability()) {
            @Override void createDirectory(Path directory) throws IOException {
                if (exactWinner) Files.createDirectory(directory);
                throw new FileAlreadyExistsException(directory.toString());
            }
        };
        try (var store = NioV1ObjectPublicationStore.open(root, operations)) {
            if (exactWinner) assertEquals(PUBLISHED_NEW, store.publish(ObjectId.fromFilename(NAME), new byte[1024]));
            else assertThrows(FileAlreadyExistsException.class, () -> store.publish(ObjectId.fromFilename(NAME), new byte[1024]));
        }
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertEquals(exactWinner ? List.of(NAME) : List.of(), snapshot.candidates().stream().map(c -> c.id().filename()).toList());
        }
        assertArrayEquals(new byte[1024], Files.readAllBytes(ignored));
        assertEquals(modified, Files.getLastModifiedTime(ignored));
        try (var entries = Files.list(upper)) { assertEquals(List.of(ignored), entries.toList()); }
    }

    @Test void initialVaultAliasCollisionFailsWithoutOverwriting() throws Exception {
        byte[] old = {1, 2, 3};
        Path upper = Files.write(root.resolve("VAULT"), old);
        var operations = new NioVaultBootstrapStorage.Operations(path -> fail("No successful install")) {
            @Override void link(Path target, Path temp) throws IOException {
                throw new FileAlreadyExistsException(target.toString());
            }
        };
        try (var store = NioVaultBootstrapStorage.open(root, operations); var stage = store.stageInitial(new byte[87])) {
            assertNull(store.openCanonicalRead());
            assertThrows(FileAlreadyExistsException.class, stage::installInitialDurably);
            assertNull(store.openCanonicalRead());
        }
        assertArrayEquals(old, Files.readAllBytes(upper));
        try (var entries = Files.list(root)) { assertEquals(List.of(upper), entries.toList()); }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void collisionReopensOnlyExactWinner(boolean exactWinner) throws Exception {
        Path directory = Files.createDirectory(root.resolve("objects-v1"));
        byte[] bytes = new byte[1024];
        Path upper = Files.write(directory.resolve(NAME.toUpperCase(Locale.ROOT)), bytes);
        var modified = Files.getLastModifiedTime(upper);
        try (var snapshot = new NioDiscoverySource(root).snapshot()) { assertTrue(snapshot.candidates().isEmpty()); }
        var operations = new NioV1ObjectPublicationStore.Operations(path -> fail("No acknowledgement barrier")) {
            @Override void link(Path target, Path temp) throws IOException {
                // Model an alias collision, or a normal exactly spelled concurrent winner.
                if (exactWinner) Files.write(target, bytes);
                throw new FileAlreadyExistsException(target.toString());
            }
            @Override byte[] readExisting(Path target, String point) throws IOException {
                assertTrue(exactWinner, "An alias must never be compared");
                return super.readExisting(target, point);
            }
        };
        try (var store = NioV1ObjectPublicationStore.open(root, operations)) {
            if (exactWinner) assertEquals(ALREADY_PRESENT_EXACT, store.publish(ObjectId.fromFilename(NAME), bytes));
            else assertThrows(FileAlreadyExistsException.class, () -> store.publish(ObjectId.fromFilename(NAME), bytes));
        }
        try (var snapshot = new NioDiscoverySource(root).snapshot()) {
            assertEquals(exactWinner ? List.of(NAME) : List.of(), snapshot.candidates().stream().map(c -> c.id().filename()).toList());
        }
        assertArrayEquals(bytes, Files.readAllBytes(upper));
        assertEquals(modified, Files.getLastModifiedTime(upper));
        try (var entries = Files.list(directory)) { assertEquals(exactWinner ? 2 : 1, entries.count()); }
    }
}
