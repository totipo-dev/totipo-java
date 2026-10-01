package dev.totipo.storage.nio;

import dev.totipo.spi.*;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;

/** Layout-only contract tests: deliberately arbitrary names and opaque, nonprotocol lengths. */
@Timeout(20)
class NioSpiTest {
    @TempDir Path root;
    private static final ObjectName NAME = new ObjectName("opaque");
    private static final byte[] BYTES = {1, 7, 3};
    private NioTotipoStore open() throws IOException { return NioTotipoStore.open(root, directory -> {}); }
    private Path directory() throws IOException { return Files.createDirectory(root.resolve("objects-v1")); }
    private PreparedVault prepare(TotipoStore store) {
        return assertInstanceOf(VaultPrepare.Prepared.class, store.prepareVault(BYTES)).vault();
    }
    private NioTotipoStore open(NioObjectStorage.Operations objects, NioVaultStorage.Operations vaults,
                               NioTotipoStore.ScanOperations scans) throws IOException {
        return NioTotipoStore.open(root, objects, vaults, scans);
    }

    @Test void constructionAndMissingNamespaceAreReadOnly() throws Exception {
        Files.write(root.resolve("junk"), BYTES);
        try (var store = open()) {
            assertInstanceOf(BoundedRead.Absent.class, store.readVault(3));
            assertEquals(new ObjectScan.Complete(List.of()), store.scanObjects());
            assertInstanceOf(BoundedRead.Absent.class, store.readObject(NAME, 3));
        }
        try (var entries = Files.list(root)) { assertEquals(List.of("junk"), entries.map(p -> p.getFileName().toString()).toList()); }
    }

    @Test void scanExposesAllExactDirectNamesKindsAndLogicalLengths() throws Exception {
        Path directory = directory();
        var names = List.of("a".repeat(64), "UPPERCASE-NAME", "junk", ".tmp", "abc", "ABC", "é", "é");
        for (var name : names) Files.write(directory.resolve(name), BYTES);
        Files.write(Files.createDirectory(directory.resolve("directory")).resolve("nested"), BYTES);
        Files.createSymbolicLink(directory.resolve("symlink"), root.resolve("absent"));
        try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            socket.bind(UnixDomainSocketAddress.of(directory.resolve("socket")));
            try (var store = open()) {
                var scan = assertInstanceOf(ObjectScan.Complete.class, store.scanObjects());
                var found = new HashMap<String, ObjectEntry>();
                for (var entry : scan.entries()) assertNull(found.put(entry.name().value(), entry));
                assertEquals(names.size() + 3, found.size());
                for (var name : names) {
                    assertEquals(EntryKind.REGULAR, found.get(name).kind());
                    assertEquals(OptionalLong.of(3), found.get(name).contentLength());
                }
                assertEquals(EntryKind.DIRECTORY, found.get("directory").kind());
                assertEquals(EntryKind.SYMLINK, found.get("symlink").kind());
                assertEquals(EntryKind.OTHER, found.get("socket").kind());
                assertEquals(OptionalLong.empty(), found.get("socket").contentLength());
                assertFalse(found.containsKey("nested"));
            }
        }
    }

    @Test void incompleteEnumerationKeepsAlreadySeenChildren() throws Exception {
        Path child = Files.write(directory().resolve("seen"), BYTES);
        var scans = new NioTotipoStore.ScanOperations() {
            @Override DirectoryStream<Path> entries(Path ignored) {
                return new DirectoryStream<>() {
                    @Override public Iterator<Path> iterator() {
                        return new Iterator<>() {
                            boolean seen;
                            @Override public boolean hasNext() {
                                if (seen) throw new DirectoryIteratorException(new IOException("interrupted"));
                                return true;
                            }
                            @Override public Path next() { seen = true; return child; }
                        };
                    }
                    @Override public void close() {}
                };
            }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), new NioVaultStorage.Operations(p -> {}), scans)) {
            var scan = assertInstanceOf(ObjectScan.Incomplete.class, store.scanObjects());
            assertEquals(List.of(new ObjectEntry(new ObjectName("seen"), EntryKind.REGULAR, OptionalLong.of(3))), scan.entries());
        }
    }

    @Test void metadataFailurePreservesNameAsUnknownAndMarksIncomplete() throws Exception {
        Files.write(directory().resolve("seen"), BYTES);
        var scans = new NioTotipoStore.ScanOperations() {
            @Override BasicFileAttributes attributes(Path entry) throws IOException { throw new IOException("attributes unavailable"); }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), new NioVaultStorage.Operations(p -> {}), scans)) {
            var scan = assertInstanceOf(ObjectScan.Incomplete.class, store.scanObjects());
            assertEquals(List.of(new ObjectEntry(new ObjectName("seen"), EntryKind.UNKNOWN, OptionalLong.empty())), scan.entries());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"file", "link"})
    void unsafeNamespaceNeverLooksEmpty(String kind) throws Exception {
        if (kind.equals("file")) Files.write(root.resolve("objects-v1"), BYTES);
        else Files.createSymbolicLink(root.resolve("objects-v1"), Files.createDirectory(root.resolve("target")));
        try (var store = open()) {
            assertEquals(StoreFailure.UNSAFE_NAMESPACE, assertInstanceOf(ObjectScan.Incomplete.class, store.scanObjects()).reason());
            assertEquals(new BoundedRead.Unavailable(StoreFailure.UNSAFE_NAMESPACE), store.readObject(NAME, 3));
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNSAFE_NAMESPACE), store.publishObject(NAME, BYTES));
        }
    }

    @ParameterizedTest @ValueSource(longs = {0, 2, 3, 4, 1099511627776L})
    void exactReadsObserveEofOrExtraByteWithBoundedAllocation(long size) throws Exception {
        Path path = directory().resolve(NAME.value());
        try (var file = new java.io.RandomAccessFile(path.toFile(), "rw")) { file.setLength(size); }
        Files.createLink(root.resolve("vault"), path);
        try (var store = open()) {
            for (var result : List.of(store.readObject(NAME, 3), store.readVault(3))) {
                if (size == 3) assertArrayEquals(new byte[3], assertInstanceOf(BoundedRead.Present.class, result).bytes());
                else if (size < 3) assertEquals(size, assertInstanceOf(BoundedRead.Undersized.class, result).observedLength());
                else assertInstanceOf(BoundedRead.Oversized.class, result);
            }
        }
        assertEquals(size, Files.size(path));
    }

    @Test void metadataIsNotPinnedAndSymlinksAreNotFollowed() throws Exception {
        Path path = Files.write(directory().resolve(NAME.value()), new byte[1024]);
        Path outside = Files.write(root.resolve("outside"), BYTES);
        try (var store = open()) {
            var entry = store.scanObjects().entries().get(0);
            assertEquals(OptionalLong.of(1024), entry.contentLength());
            Files.write(path, new byte[17]);
            assertEquals(new BoundedRead.Undersized(17), store.readObject(entry.name(), 1024));
            Files.delete(path); Files.createSymbolicLink(path, outside);
            assertEquals(new BoundedRead.WrongKind(EntryKind.SYMLINK), store.readObject(entry.name(), 3));
            Files.delete(path); Files.createDirectory(path);
            assertEquals(new BoundedRead.WrongKind(EntryKind.DIRECTORY), store.readObject(entry.name(), 3));
            Files.delete(path);
            assertInstanceOf(BoundedRead.Absent.class, store.readObject(entry.name(), 3));
        }
    }

    @Test void zeroAndMaximumReadBoundsDoNotOverflowOrPreallocateTheBound() throws Exception {
        Path path = Files.write(directory().resolve(NAME.value()), BYTES);
        try (var store = open()) {
            assertEquals(new BoundedRead.Undersized(3), store.readObject(NAME, Integer.MAX_VALUE));
            assertInstanceOf(BoundedRead.Oversized.class, store.readObject(NAME, 0));
            Files.write(path, new byte[0]);
            assertArrayEquals(new byte[0], assertInstanceOf(BoundedRead.Present.class, store.readObject(NAME, 0)).bytes());
            assertThrows(IllegalArgumentException.class, () -> store.readObject(NAME, -1));
        }
    }

    @Test void exactNamesNeverAcceptCaseOrNormalizationAliases() throws Exception {
        Path directory = directory();
        Files.write(directory.resolve("ABCDEF"), BYTES);
        Files.write(directory.resolve("é"), BYTES);
        Files.write(root.resolve("VAULT"), BYTES);
        try (var store = open()) {
            assertInstanceOf(BoundedRead.Absent.class, store.readObject(new ObjectName("abcdef"), 3));
            assertInstanceOf(BoundedRead.Absent.class, store.readObject(new ObjectName("é"), 3));
            assertInstanceOf(BoundedRead.Absent.class, store.readVault(3));
            assertInstanceOf(BoundedRead.Present.class, store.readObject(new ObjectName("ABCDEF"), 3));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"", ".", "..", "../vault", "nested/file", "/vault"})
    void unsafeChildNamesCannotTraverseOrPublish(String name) throws Exception {
        var value = new ObjectName(name);
        assertEquals(name, value.value()); // ObjectName preserves input; storage checks representability.
        try (var store = open()) {
            assertEquals(new BoundedRead.Unavailable(StoreFailure.UNSAFE_NAMESPACE), store.readObject(value, 3));
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNSAFE_NAMESPACE), store.publishObject(value, BYTES));
        }
        assertFalse(Files.exists(root.resolve("objects-v1")));
    }

    @Test void publicationIsOpaqueImmutableAndExactExistingForcesAgain() throws Exception {
        var events = new ArrayList<String>();
        var operations = new NioObjectStorage.Operations(p -> {}) {
            @Override void at(String point) { events.add(point); }
        };
        byte[] input = BYTES.clone();
        try (var store = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            assertInstanceOf(ObjectWrite.Written.class, store.publishObject(NAME, input));
            assertArrayEquals(BYTES, input);
            input[0] = 42;
            assertArrayEquals(BYTES, assertInstanceOf(BoundedRead.Present.class, store.readObject(NAME, 3)).bytes());
            events.clear();
            assertInstanceOf(ObjectWrite.AlreadyPresentExact.class, store.publishObject(NAME, BYTES));
            assertTrue(events.containsAll(List.of("existing-force", "existing-directory-sync", "existing-root-sync", "existing-confirm")));
            assertInstanceOf(ObjectWrite.ExistingDifferent.class, store.publishObject(NAME, input));
            assertArrayEquals(BYTES, Files.readAllBytes(root.resolve("objects-v1").resolve(NAME.value())));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"stage-sync", "before-link", "after-link", "post-link-sync", "directory-sync"})
    void publicationCertaintyAndExactRetry(String point) throws Exception {
        var operations = new NioObjectStorage.Operations(p -> {}) {
            boolean fail = true;
            @Override void at(String at) throws IOException {
                if (fail && point.equals(at)) { fail = false; throw new IOException("lost acknowledgement"); }
            }
        };
        try (var store = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            var first = store.publishObject(NAME, BYTES);
            boolean before = Set.of("stage-sync", "before-link").contains(point);
            if (before) assertInstanceOf(ObjectWrite.Failed.class, first);
            else assertInstanceOf(ObjectWrite.Uncertain.class, first);
            assertEquals(!before, Files.exists(root.resolve("objects-v1").resolve(NAME.value())));
            if (before) assertInstanceOf(ObjectWrite.Written.class, store.publishObject(NAME, BYTES));
            else assertInstanceOf(ObjectWrite.AlreadyPresentExact.class, store.publishObject(NAME, BYTES));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"existing-force", "existing-directory-sync", "existing-root-sync", "existing-confirm"})
    void exactExistingBarrierFailureCannotAcknowledgeSuccess(String point) throws Exception {
        Files.write(directory().resolve(NAME.value()), BYTES);
        var operations = new NioObjectStorage.Operations(p -> {}) {
            @Override void at(String at) throws IOException { if (point.equals(at)) throw new IOException("barrier failed"); }
        };
        try (var store = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            assertInstanceOf(ObjectWrite.Uncertain.class, store.publishObject(NAME, BYTES));
        }
    }

    @Test void aliasCollisionIsNeverExactExisting() throws Exception {
        Path upper = Files.write(directory().resolve("OPAQUE"), BYTES);
        var operations = new NioObjectStorage.Operations(p -> {}) {
            @Override void link(Path target, Path temp) throws IOException { throw new FileAlreadyExistsException(target.toString()); }
            @Override byte[] readExisting(Path path, String point, int limit) { return fail("Alias must not be read"); }
        };
        try (var store = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNSAFE_NAMESPACE), store.publishObject(NAME, BYTES));
        }
        assertArrayEquals(BYTES, Files.readAllBytes(upper));
    }

    @Test void preparationIsPrivateAndCloseAbandonsIt() throws Exception {
        Files.write(root.resolve("vault"), new byte[]{9});
        try (var store = open()) {
            byte[] input = BYTES.clone();
            var stage = assertInstanceOf(VaultPrepare.Prepared.class, store.prepareVault(input)).vault();
            assertArrayEquals(BYTES, input); input[0] = 8;
            assertArrayEquals(BYTES, assertInstanceOf(BoundedRead.Present.class, stage.readBack(3)).bytes());
            assertArrayEquals(new byte[]{9}, Files.readAllBytes(root.resolve("vault")));
            stage.close(); stage.close();
            assertThrows(IllegalStateException.class, () -> stage.readBack(3));
        }
        try (var entries = Files.list(root)) { assertEquals(List.of("vault"), entries.map(p -> p.getFileName().toString()).toList()); }
    }

    @ParameterizedTest @ValueSource(strings = {"short", "long", "directory", "symlink", "missing"})
    void stagedReadBackFreshlyObservesActualRepresentation(String mode) throws Exception {
        try (var store = open(); var stage = prepare(store)) {
            Path temp;
            try (var files = Files.list(root)) { temp = files.findFirst().orElseThrow(); }
            switch (mode) {
                case "short" -> Files.write(temp, new byte[2]);
                case "long" -> Files.write(temp, new byte[4]);
                case "directory" -> { Files.delete(temp); Files.createDirectory(temp); }
                case "symlink" -> { Files.delete(temp); Files.createSymbolicLink(temp, Files.write(root.resolve("outside"), BYTES)); }
                case "missing" -> Files.delete(temp);
                default -> fail();
            }
            var result = stage.readBack(3);
            switch (mode) {
                case "short" -> assertEquals(new BoundedRead.Undersized(2), result);
                case "long" -> assertInstanceOf(BoundedRead.Oversized.class, result);
                case "directory" -> assertEquals(new BoundedRead.WrongKind(EntryKind.DIRECTORY), result);
                case "symlink" -> assertEquals(new BoundedRead.WrongKind(EntryKind.SYMLINK), result);
                case "missing" -> assertInstanceOf(BoundedRead.Absent.class, result);
                default -> fail();
            }
            assertFalse(Files.exists(root.resolve("vault")));
        }
    }

    @Test void prepareFailureDoesNotChangeCanonical() throws Exception {
        Files.write(root.resolve("vault"), BYTES);
        var operations = new NioVaultStorage.Operations(p -> {}) {
            @Override void syncStage(java.nio.channels.FileChannel channel) throws IOException { throw new IOException("stage failed"); }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), operations, new NioTotipoStore.ScanOperations())) {
            assertInstanceOf(VaultPrepare.Failed.class, store.prepareVault(new byte[]{9}));
            assertArrayEquals(BYTES, Files.readAllBytes(root.resolve("vault")));
        }
    }

    @Test void inaccessibleStagingNamespaceIsUnavailable() throws Exception {
        try (var store = open(); var stage = prepare(store)) {
            Path moved = root.resolveSibling(root.getFileName() + "-unavailable");
            Files.move(root, moved);
            try { assertInstanceOf(BoundedRead.Unavailable.class, stage.readBack(3)); }
            finally { Files.move(moved, root); }
        }
    }

    @Test void initialInstallNeverOverwritesAndConsumesHandle() throws Exception {
        try (var store = open(); var stage = prepare(store)) {
            assertInstanceOf(VaultInstall.Installed.class, stage.installCanonicalIfAbsent());
            assertThrows(IllegalStateException.class, stage::replaceCanonical);
            assertThrows(IllegalStateException.class, stage::installCanonicalIfAbsent);
            try (var next = assertInstanceOf(VaultPrepare.Prepared.class, store.prepareVault(new byte[]{8})).vault()) {
                assertInstanceOf(VaultInstall.AlreadyPresent.class, next.installCanonicalIfAbsent());
                assertThrows(IllegalStateException.class, next::installCanonicalIfAbsent);
            }
            assertArrayEquals(BYTES, Files.readAllBytes(root.resolve("vault")));
        }
    }

    @Test void vaultCaseAliasCollisionIsNotAlreadyPresent() throws Exception {
        Files.write(root.resolve("VAULT"), new byte[]{9});
        var operations = new NioVaultStorage.Operations(p -> {}) {
            @Override void link(Path target, Path temp) throws IOException { throw new FileAlreadyExistsException(target.toString()); }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), operations, new NioTotipoStore.ScanOperations());
             var stage = prepare(store)) {
            assertInstanceOf(VaultInstall.Failed.class, stage.installCanonicalIfAbsent());
            assertArrayEquals(new byte[]{9}, Files.readAllBytes(root.resolve("VAULT")));
            assertFalse(Files.exists(root.resolve("vault")));
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void canonicalMutationAcknowledgementFailureIsUncertain(boolean replace) throws Exception {
        if (replace) Files.write(root.resolve("vault"), new byte[]{9});
        try (var store = NioTotipoStore.open(root, p -> { throw new IOException("lost directory acknowledgement"); });
             var stage = prepare(store)) {
            if (replace) assertInstanceOf(VaultReplace.Uncertain.class, stage.replaceCanonical());
            else assertInstanceOf(VaultInstall.Uncertain.class, stage.installCanonicalIfAbsent());
            assertThrows(IllegalStateException.class, stage::replaceCanonical);
            assertArrayEquals(BYTES, Files.readAllBytes(root.resolve("vault")));
        }
    }

    @Test void replacementPreconditionFailureIsDefiniteAndHasNoStaleMeaning() throws Exception {
        try (var store = open(); var stage = prepare(store)) {
            assertInstanceOf(VaultReplace.Failed.class, stage.replaceCanonical());
            assertFalse(Files.exists(root.resolve("vault")));
            assertThrows(IllegalStateException.class, stage::replaceCanonical);
        }
    }

    @Test void initialPreconditionFailureIsDefinite() throws Exception {
        try (var store = open(); var stage = prepare(store)) {
            Path moved = root.resolveSibling(root.getFileName() + "-moved");
            Files.move(root, moved);
            try { assertInstanceOf(VaultInstall.Failed.class, stage.installCanonicalIfAbsent()); }
            finally { Files.move(moved, root); }
            assertFalse(Files.exists(root.resolve("vault")));
        }
    }

    @Test void replacementUsesSameStageAndAllowsNonAtomicProvider() throws Exception {
        Files.write(root.resolve("vault"), new byte[]{9});
        var operations = new NioVaultStorage.Operations(p -> {}) {
            @Override void atomicMove(Path temp, Path target) throws IOException {
                throw new AtomicMoveNotSupportedException(temp.toString(), target.toString(), "injected unsupported");
            }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), operations, new NioTotipoStore.ScanOperations());
             var stage = prepare(store)) {
            Path temp;
            try (var entries = Files.list(root)) { temp = entries.filter(p -> !p.getFileName().toString().equals("vault")).findFirst().orElseThrow(); }
            byte[] changed = {4, 5, 6};
            Files.write(temp, changed);
            assertArrayEquals(changed, assertInstanceOf(BoundedRead.Present.class, stage.readBack(3)).bytes());
            assertInstanceOf(VaultReplace.Replaced.class, stage.replaceCanonical());
            assertArrayEquals(changed, Files.readAllBytes(root.resolve("vault")));
        }
    }

    @Test void closedStoreCleansStagesAndNeverCanonical() throws Exception {
        Files.write(root.resolve("vault"), BYTES);
        var store = open(); var stage = prepare(store);
        store.close(); store.close(); stage.close();
        assertThrows(IllegalStateException.class, store::scanObjects);
        assertThrows(IllegalStateException.class, stage::replaceCanonical);
        try (var entries = Files.list(root)) { assertEquals(List.of("vault"), entries.map(p -> p.getFileName().toString()).toList()); }
    }

    @Test void nonAtomicPartialReplacementIsUncertainAndNeverRolledBack() throws Exception {
        Files.write(root.resolve("vault"), new byte[]{9});
        var operations = new NioVaultStorage.Operations(p -> {}) {
            @Override void move(Path temp, Path target) throws IOException {
                Files.write(target, new byte[]{1}); // Model a weaker provider's partial copy.
                throw new IOException("copy acknowledgement lost");
            }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), operations, new NioTotipoStore.ScanOperations());
             var stage = prepare(store)) {
            assertInstanceOf(VaultReplace.Uncertain.class, stage.replaceCanonical());
            assertArrayEquals(new byte[]{1}, Files.readAllBytes(root.resolve("vault")));
        }
        assertArrayEquals(new byte[]{1}, Files.readAllBytes(root.resolve("vault")));
    }

    @Test void uncheckedFailureAfterObjectInstallationEscapesWithoutRollback() throws Exception {
        var operations = new NioObjectStorage.Operations(p -> {}) {
            @Override void at(String point) {
                if (point.equals("after-link")) throw new IllegalStateException("unexpected provider bug");
            }
        };
        try (var store = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            assertThrows(IllegalStateException.class, () -> store.publishObject(NAME, BYTES));
            assertArrayEquals(BYTES, Files.readAllBytes(root.resolve("objects-v1").resolve(NAME.value())));
        }
    }

    @Test void valueOwnershipAndDuplicateScanValidation() {
        byte[] source = BYTES.clone();
        var present = new BoundedRead.Present(source); source[0] = 9;
        present.bytes()[0] = 8;
        assertArrayEquals(BYTES, present.bytes());
        var entry = new ObjectEntry(NAME, EntryKind.REGULAR, OptionalLong.of(3));
        assertThrows(IllegalArgumentException.class, () -> new ObjectScan.Complete(List.of(entry, entry)));
        assertThrows(IllegalArgumentException.class, () -> new ObjectScan.Incomplete(List.of(entry, entry), StoreFailure.UNAVAILABLE));
        var entries = new ArrayList<>(List.of(entry));
        var scan = new ObjectScan.Complete(entries); entries.clear();
        assertEquals(List.of(entry), scan.entries());
    }

    @Test void reopenedProviderRequiresRootBarrierBeforeEveryNewObjectMutation() throws Exception {
        var events = new ArrayList<String>();
        class Operations extends NioObjectStorage.Operations {
            boolean failRoot = true;
            Operations() { super(p -> {}); }
            @Override void sync(Path directory, String point) throws IOException {
                if (point.equals("root-sync")) {
                    assertEquals(root, directory);
                    events.add("root-enter");
                    if (failRoot) throw new IOException("root acknowledgement lost");
                    super.sync(directory, point);
                    events.add("root-acknowledged");
                } else super.sync(directory, point);
            }
            @Override void link(Path target, Path temp) throws IOException {
                assertEquals(List.of("root-enter", "root-acknowledged"), events);
                assertFalse(Files.exists(target));
                events.add("object-mutation");
                super.link(target, temp);
            }
        }
        Path target = root.resolve("objects-v1").resolve(NAME.value());
        try (var first = open(new Operations(), new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNAVAILABLE), first.publishObject(NAME, BYTES));
            assertTrue(Files.isDirectory(target.getParent()));
            assertFalse(Files.exists(target));
            assertEquals(List.of("root-enter"), events);
        }
        events.clear();
        var operations = new Operations();
        try (var reopened = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            reopened.scanObjects(); reopened.readVault(3); reopened.readObject(NAME, 3);
            assertTrue(events.isEmpty(), "Opening and observations must not perform durability work");
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNAVAILABLE), reopened.publishObject(NAME, BYTES));
            assertEquals(List.of("root-enter"), events);
            assertFalse(Files.exists(target));
            events.clear(); operations.failRoot = false;
            assertInstanceOf(ObjectWrite.Written.class, reopened.publishObject(NAME, BYTES));
            assertEquals(List.of("root-enter", "root-acknowledged", "object-mutation"), events);
            events.clear(); operations.failRoot = true;
            var second = new ObjectName("second");
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNAVAILABLE), reopened.publishObject(second, BYTES));
            assertEquals(List.of("root-enter"), events);
            assertFalse(Files.exists(target.getParent().resolve(second.value())));
            // Exact-existing recovery keeps its own stronger barrier, not the new-object barrier.
            assertInstanceOf(ObjectWrite.AlreadyPresentExact.class, reopened.publishObject(NAME, BYTES));
        }
    }

    @Test void collidingHostileNamesUseSortedScanValidationAndExactDuplicateChecks() throws Exception {
        Path directory = directory();
        var attributes = Files.readAttributes(Files.write(root.resolve("metadata-fixture"), BYTES), BasicFileAttributes.class);
        var children = new ArrayList<Path>();
        for (int bits = 0; bits < 16384; bits++) {
            var name = new StringBuilder();
            for (int bit = 0; bit < 14; bit++) name.append((bits & (1 << bit)) == 0 ? "Aa" : "BB");
            assertEquals("Aa".repeat(14).hashCode(), name.toString().hashCode());
            children.add(directory.resolve(name.toString()));
        }
        Collections.shuffle(children, new Random(173));
        var scans = new NioTotipoStore.ScanOperations() {
            @Override DirectoryStream<Path> entries(Path ignored) {
                return new DirectoryStream<>() {
                    @Override public Iterator<Path> iterator() { return children.iterator(); }
                    @Override public void close() {}
                };
            }
            @Override BasicFileAttributes attributes(Path ignored) { return attributes; }
        };
        try (var store = open(new NioObjectStorage.Operations(p -> {}), new NioVaultStorage.Operations(p -> {}), scans)) {
            var scan = assertInstanceOf(ObjectScan.Complete.class, store.scanObjects());
            assertEquals(16384, scan.entries().size());
            for (int i = 1; i < scan.entries().size(); i++)
                assertTrue(scan.entries().get(i - 1).name().value().compareTo(scan.entries().get(i).name().value()) < 0);
            var duplicate = new ArrayList<>(scan.entries());
            duplicate.add(scan.entries().get(7000));
            assertThrows(IllegalArgumentException.class, () -> new ObjectScan.Complete(duplicate));
            assertThrows(IllegalArgumentException.class, () -> new ObjectScan.Incomplete(duplicate, StoreFailure.UNAVAILABLE));
            children.add(children.get(7000));
            var incomplete = assertInstanceOf(ObjectScan.Incomplete.class, store.scanObjects());
            assertEquals(StoreFailure.UNAVAILABLE, incomplete.reason());
            assertEquals(scan.entries(), incomplete.entries(), "Provider duplicates are retained once, with an incomplete result");
        }
    }

    @Test void namespaceCreationAliasCollisionIsUnsafe() throws Exception {
        Files.createDirectory(root.resolve("OBJECTS-V1"));
        var operations = new NioObjectStorage.Operations(p -> fail("No mutation barrier for an unsafe namespace")) {
            @Override void createDirectory(Path directory) throws IOException {
                throw new FileAlreadyExistsException(directory.toString());
            }
        };
        try (var store = open(operations, new NioVaultStorage.Operations(p -> {}), new NioTotipoStore.ScanOperations())) {
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNSAFE_NAMESPACE), store.publishObject(NAME, BYTES));
            assertFalse(Files.exists(root.resolve("objects-v1")));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"directory", "symlink"})
    void structurallyBlockedObjectPublicationIsUnsafe(String kind) throws Exception {
        Path target = directory().resolve(NAME.value());
        EntryKind expected;
        if (kind.equals("directory")) { Files.createDirectory(target); expected = EntryKind.DIRECTORY; }
        else { Files.createSymbolicLink(target, root.resolve("missing")); expected = EntryKind.SYMLINK; }
        try (var store = open()) {
            assertEquals(expected, store.scanObjects().entries().get(0).kind());
            assertEquals(new BoundedRead.WrongKind(expected), store.readObject(NAME, 3));
            assertEquals(new ObjectWrite.Failed(StoreFailure.UNSAFE_NAMESPACE), store.publishObject(NAME, BYTES));
        }
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void rootSafetyAndOrdinaryUnavailabilityRemainDistinct(boolean structurallyUnsafe) throws Exception {
        try (var store = open()) {
            Path moved = root.resolveSibling(root.getFileName() + "-moved");
            Files.move(root, moved);
            try {
                if (structurallyUnsafe) Files.write(root, BYTES);
                var reason = structurallyUnsafe ? StoreFailure.UNSAFE_NAMESPACE : StoreFailure.UNAVAILABLE;
                assertEquals(reason, assertInstanceOf(ObjectScan.Incomplete.class, store.scanObjects()).reason());
                assertEquals(new BoundedRead.Unavailable(reason), store.readVault(3));
                assertEquals(new BoundedRead.Unavailable(reason), store.readObject(NAME, 3));
                assertEquals(new ObjectWrite.Failed(reason), store.publishObject(NAME, BYTES));
            } finally {
                if (structurallyUnsafe) Files.delete(root);
                Files.move(moved, root);
            }
        }
    }
}
