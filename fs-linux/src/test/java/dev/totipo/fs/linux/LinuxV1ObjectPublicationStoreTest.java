package dev.totipo.fs.linux;

import dev.totipo.format.ObjectId;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.V1ObjectPublicationStore.PublicationResult.*;

@Timeout(40)
class LinuxV1ObjectPublicationStoreTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path root;
    static ObjectId id(int n) { byte[] b = new byte[32]; b[0] = (byte) n; return ObjectId.fromFilename(HexFormat.of().formatHex(b)); }
    static byte[] bytes() { byte[] b = new byte[1024]; new Random(7).nextBytes(b); return b; }
    Path target() { return root.resolve("objects-v1").resolve(id(1).filename()); }
    static List<String> names(Path dir) throws IOException {
        try (var paths = Files.list(dir)) { return paths.map(p -> p.getFileName().toString()).sorted().toList(); }
    }
    @Test void lazyOpenInputValidationAndClose() throws Exception {
        var store = LinuxV1ObjectPublicationStore.open(root);
        assertEquals(List.of(), names(root));
        assertThrows(NullPointerException.class, () -> store.publishDurably(null, bytes()));
        assertThrows(NullPointerException.class, () -> store.publishDurably(id(1), null));
        for (int size : new int[]{0, 1023, 1025})
            assertThrows(IllegalArgumentException.class, () -> store.publishDurably(id(1), new byte[size]));
        store.close(); store.close();
        assertEquals(List.of(), names(root));
        assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
    }
    @Test void exactNewAndExistingBarrierOrderModesAndShortWrites() throws Exception {
        var f = new ObjectPublicationFaults(); f.writeLimit = 7;
        try (var store = f.open(root)) {
            assertEquals(PUBLISHED_NEW, store.publishDurably(id(1), bytes()));
            assertArrayEquals(bytes(), Files.readAllBytes(target()));
            assertEquals(List.of("objects-v1"), names(root));
            assertEquals(List.of(id(1).filename()), names(target().getParent()));
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target()));
            assertEquals(List.of("snapshot", "mkdir", "namespace-sync", "root-sync", "temporary", "stage-sync",
                    "stage-read", "before-link", "after-link", "post-link-sync", "directory-sync", "final-read"),
                    f.events.stream().filter(e -> !e.equals("write")).toList());
            Files.setPosixFilePermissions(target(), PosixFilePermissions.fromString("rw-r--r--"));
            f.events.clear();
            assertEquals(ALREADY_PRESENT_EXACT, store.publishDurably(id(1), bytes()));
            assertEquals(List.of("snapshot", "temporary", "stage-sync", "stage-read", "before-link",
                    "existing-pinned", "existing-sync", "existing-directory-sync"),
                    f.events.stream().filter(e -> !e.equals("write")).toList());
            assertEquals(PosixFilePermissions.fromString("rw-r--r--"), Files.getPosixFilePermissions(target()));
        }
    }
    @Test void defensiveSnapshotPrecedesAllNativeWrites() throws Exception {
        byte[] caller = bytes(); var f = new ObjectPublicationFaults();
        f.action = point -> { if (point.equals("snapshot")) Arrays.fill(caller, (byte) 99); };
        try (var store = f.open(root)) { assertEquals(PUBLISHED_NEW, store.publishDurably(id(1), caller)); }
        assertArrayEquals(bytes(), Files.readAllBytes(target()));
        assertEquals(99, caller[0]);
    }
    @Test void rootContractAndReplacementResistance() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> LinuxV1ObjectPublicationStore.open(Path.of("relative")));
        assertThrows(IOException.class, () -> LinuxV1ObjectPublicationStore.open(root.resolve("missing")));
        var file = Files.write(root.resolve("file"), new byte[0]);
        assertThrows(IOException.class, () -> LinuxV1ObjectPublicationStore.open(file));
        var link = Files.createSymbolicLink(root.resolve("link"), root);
        assertThrows(IOException.class, () -> LinuxV1ObjectPublicationStore.open(link));
        try (var zip = FileSystems.newFileSystem(java.net.URI.create("jar:" + root.resolve("x.zip").toUri()), Map.of("create", "true"))) {
            assertThrows(IllegalArgumentException.class, () -> LinuxV1ObjectPublicationStore.open(zip.getPath("/")));
        }
        Path configured = Files.createDirectory(root.resolve("configured")), moved = root.resolve("moved");
        try (var store = LinuxV1ObjectPublicationStore.open(configured)) {
            Files.move(configured, moved); Files.createDirectory(configured);
            assertEquals(PUBLISHED_NEW, store.publishDurably(id(1), bytes()));
            assertEquals(List.of(), names(configured));
            assertArrayEquals(bytes(), Files.readAllBytes(moved.resolve("objects-v1").resolve(id(1).filename())));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"file", "symlink", "fifo", "socket"})
    void hostileNamespace(String kind) throws Exception {
        // Short paths only for Unix socket address length; no durability evidence taken here.
        Path dir = kind.equals("socket") ? Files.createTempDirectory("obj-") : root;
        Path child = dir.resolve("objects-v1");
        try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            switch (kind) {
                case "file" -> Files.write(child, new byte[]{7});
                case "symlink" -> Files.createSymbolicLink(child, Path.of("/dev/zero"));
                case "fifo" -> LinuxSecureSourceTest.fifo(child);
                case "socket" -> socket.bind(UnixDomainSocketAddress.of(child));
                default -> throw new AssertionError();
            }
            var before = Files.readAttributes(child, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).fileKey();
            try (var store = LinuxV1ObjectPublicationStore.open(dir)) {
                assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
            }
            assertEquals(before, Files.readAttributes(child, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).fileKey());
        } finally { if (!dir.equals(root)) { Files.delete(child); Files.delete(dir); } }
    }
    @ParameterizedTest @ValueSource(strings = {"directory", "file", "symlink", "fifo"})
    void mkdirEexistRaceRebindsOnlyDirectory(String kind) throws Exception {
        var f = new ObjectPublicationFaults();
        f.action = point -> {
            if (point.equals("mkdir")) switch (kind) {
                case "directory" -> Files.createDirectory(root.resolve("objects-v1"));
                case "file" -> Files.write(root.resolve("objects-v1"), new byte[]{3});
                case "symlink" -> Files.createSymbolicLink(root.resolve("objects-v1"), root);
                case "fifo" -> {
                    try { LinuxSecureSourceTest.fifo(root.resolve("objects-v1")); }
                    catch (Exception e) { throw new IOException(e); }
                }
                default -> throw new AssertionError();
            }
        };
        try (var store = f.open(root)) {
            if (kind.equals("directory")) assertEquals(PUBLISHED_NEW, store.publishDurably(id(1), bytes()));
            else assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"mkdir", "namespace-sync", "root-sync", "temporary", "write", "zero",
            "stage-sync", "stage-read", "before-link", "after-link", "post-link-sync", "directory-sync", "final-read"})
    void faultMatrixNeverRollsBack(String point) throws Exception {
        var f = new ObjectPublicationFaults(); f.fail = point;
        try (var store = f.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes())); }
        boolean linked = Set.of("after-link", "post-link-sync", "directory-sync", "final-read").contains(point);
        if (point.equals("mkdir")) assertEquals(List.of(), names(root));
        else {
            assertEquals(List.of("objects-v1"), names(root));
            assertEquals(linked ? List.of(id(1).filename()) : List.of(), names(root.resolve("objects-v1")));
        }
        if (linked) assertArrayEquals(bytes(), Files.readAllBytes(target()));
    }
    @Test void unsupportedNativeOperationsDoNotFallBack() throws Exception {
        for (boolean stage : new boolean[]{true, false}) {
            var f = new ObjectPublicationFaults();
            if (stage) f.temporaryErrno = LinuxAbi.EOPNOTSUPP; else f.linkErrno = LinuxAbi.EOPNOTSUPP;
            try (var store = f.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes())); }
            assertEquals(List.of(), names(root.resolve("objects-v1")));
        }
    }
    @Test void failedNamespaceBarrierIsNotCachedAndRetryRepeatsBothBarriers() throws Exception {
        var f = new ObjectPublicationFaults(); f.fail = "root-sync";
        try (var store = f.open(root)) {
            assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
            assertEquals(List.of(), names(root.resolve("objects-v1")));
            f.events.clear(); f.fail = "";
            assertEquals(PUBLISHED_NEW, store.publishDurably(id(1), bytes()));
            assertTrue(f.events.indexOf("namespace-sync") < f.events.indexOf("root-sync"));
            assertTrue(f.events.indexOf("root-sync") < f.events.indexOf("temporary"));
        }
    }
    @Test void mkdirThenOpenDoesNotClaimCreatorInodeContinuity() throws Exception {
        var operations = new LinuxV1ObjectPublicationStore.Operations() {
            @Override void mkdir(LinuxLibc libc, LinuxFd parent) throws IOException {
                super.mkdir(libc, parent);
                Files.move(root.resolve("objects-v1"), root.resolve("created"));
                Files.createDirectory(root.resolve("objects-v1"));
            }
        };
        try (var store = LinuxV1ObjectPublicationStore.open(root, operations)) {
            assertEquals(PUBLISHED_NEW, store.publishDurably(id(1), bytes()));
        }
        assertEquals(List.of(), names(root.resolve("created")));
        assertArrayEquals(bytes(), Files.readAllBytes(target()));
    }
    @ParameterizedTest @ValueSource(strings = {"absent", "symlink", "file"})
    void cachedNamespaceMustStillBeCanonical(String form) throws Exception {
        var f = new ObjectPublicationFaults();
        try (var store = f.open(root)) {
            store.publishDurably(id(2), bytes());
            Files.move(root.resolve("objects-v1"), root.resolve("old"));
            if (form.equals("symlink")) Files.createSymbolicLink(root.resolve("objects-v1"), root.resolve("old"));
            if (form.equals("file")) Files.write(root.resolve("objects-v1"), new byte[0]);
            f.events.clear();
            assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
            assertFalse(f.events.contains("before-link"));
            assertFalse(Files.exists(root.resolve("old").resolve(id(1).filename())));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"existing-sync", "existing-directory-sync"})
    void exactExistingRequiresBothBarriers(String point) throws Exception {
        Files.write(Files.createDirectory(root.resolve("objects-v1")).resolve(id(1).filename()), bytes());
        var f = new ObjectPublicationFaults(); f.fail = point;
        try (var store = f.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes())); }
        assertArrayEquals(bytes(), Files.readAllBytes(target()));
    }
    @ParameterizedTest @ValueSource(longs = {0, 1023, 1025, 1099511627776L})
    void wrongSizeReadsAreBounded(long length) throws Exception {
        Files.createDirectory(root.resolve("objects-v1"));
        try (var file = FileChannel.open(target(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            if (length > 0) { file.position(length - 1); file.write(ByteBuffer.wrap(new byte[]{0})); }
        }
        try (var store = LinuxV1ObjectPublicationStore.open(root)) {
            assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
        }
        assertEquals(length, Files.size(target()));
    }
    @Test void collisionsAndUnrelatedEntriesAreUntouched() throws Exception {
        Path dir = Files.createDirectory(root.resolve("objects-v1"));
        for (String name : List.of("A".repeat(64), "a".repeat(63), "a".repeat(65), ".tmp", "conflict", "unrelated"))
            Files.write(dir.resolve(name), new byte[]{7});
        Files.createDirectory(dir.resolve("nested")); Files.createDirectory(root.resolve("objects-v2"));
        byte[] collision = new byte[1024]; Files.write(target(), collision); var before = names(dir);
        try (var store = LinuxV1ObjectPublicationStore.open(root)) {
            assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
            assertEquals(PUBLISHED_NEW, store.publishDurably(id(2), bytes()));
        }
        assertArrayEquals(collision, Files.readAllBytes(target()));
        assertTrue(names(dir).containsAll(before)); assertEquals(before.size() + 1, names(dir).size());
        assertEquals(List.of(), names(root.resolve("objects-v2")));
    }
    @ParameterizedTest @ValueSource(strings = {"symlink", "directory", "fifo", "socket", "unreadable"})
    void hostileExistingTarget(String kind) throws Exception {
        Path dir = kind.equals("socket") ? Files.createTempDirectory("o") : root;
        Path namespace = Files.createDirectory(dir.resolve("objects-v1")), target = namespace.resolve(id(1).filename());
        try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            switch (kind) {
                case "symlink" -> Files.createSymbolicLink(target, Path.of("/dev/zero"));
                case "directory" -> Files.createDirectory(target);
                case "fifo" -> LinuxSecureSourceTest.fifo(target);
                case "socket" -> socket.bind(UnixDomainSocketAddress.of(target));
                case "unreadable" -> { Files.write(target, bytes()); Files.setPosixFilePermissions(target, Set.of()); }
                default -> throw new AssertionError();
            }
            try (var store = LinuxV1ObjectPublicationStore.open(dir)) {
                assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
            }
            assertTrue(Files.exists(target, LinkOption.NOFOLLOW_LINKS));
        } finally {
            if (kind.equals("unreadable")) Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
            if (!dir.equals(root)) { Files.delete(target); Files.delete(namespace); Files.delete(dir); }
        }
    }
    @ParameterizedTest @ValueSource(strings = {"cached", "stage-read", "before-link", "directory-sync"})
    void namespaceReplacementPreventsAcknowledgement(String point) throws Exception {
        var f = new ObjectPublicationFaults(); Path old = root.resolve("detached");
        try (var store = f.open(root)) {
            if (point.equals("cached")) store.publishDurably(id(2), bytes());
            f.action = event -> { if (event.equals(point)) replaceNamespace(old); };
            if (point.equals("cached")) replaceNamespace(old);
            assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes()));
            assertEquals(List.of(), names(root.resolve("objects-v1")));
            assertEquals(Set.of("before-link", "directory-sync").contains(point), Files.exists(old.resolve(id(1).filename())));
        }
    }
    void replaceNamespace(Path old) throws IOException {
        Files.move(root.resolve("objects-v1"), old); Files.createDirectory(root.resolve("objects-v1"));
    }
    @ParameterizedTest @ValueSource(strings = {"delete", "replace", "mutate"})
    void postLinkTargetChangesFailWithoutRepair(String change) throws Exception {
        var f = new ObjectPublicationFaults();
        f.action = point -> {
            if (point.equals("directory-sync")) switch (change) {
                case "delete" -> Files.delete(target());
                case "replace" -> { Files.move(target(), root.resolve("old")); Files.write(target(), bytes()); }
                case "mutate" -> Files.write(target(), new byte[1024]);
                default -> throw new AssertionError();
            }
        };
        try (var store = f.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes())); }
        if (change.equals("mutate")) assertArrayEquals(new byte[1024], Files.readAllBytes(target()));
        if (change.equals("delete")) assertFalse(Files.exists(target()));
    }
    @ParameterizedTest @ValueSource(strings = {"existing-pinned", "existing-sync"})
    void existingStablePinAndMutationChecks(String point) throws Exception {
        Files.write(Files.createDirectory(root.resolve("objects-v1")).resolve(id(1).filename()), bytes());
        var f = new ObjectPublicationFaults();
        f.action = event -> {
            if (event.equals(point)) {
                if (point.equals("existing-pinned")) { Files.move(target(), root.resolve("old")); Files.write(target(), bytes()); }
                else Files.write(target(), new byte[1024]);
            }
        };
        try (var store = f.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes())); }
        if (point.equals("existing-pinned")) assertTrue(f.events.contains("existing-directory-sync"));
    }
    @Test void corruptStageReadbackPreventsLink() throws Exception {
        var f = new ObjectPublicationFaults();
        f.action = point -> { if (point.equals("stage-read")) Files.write(f.stage.procPath(), new byte[1024]); };
        try (var store = f.open(root)) { assertThrows(IOException.class, () -> store.publishDurably(id(1), bytes())); }
        assertFalse(f.events.contains("before-link")); assertEquals(List.of(), names(root.resolve("objects-v1")));
    }
    @ParameterizedTest @ValueSource(strings = {"same", "collision", "different"})
    void independentConcurrentPublishersAndNamespaceCreators(String mode) throws Exception {
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                final int n = i;
                futures.add(executor.submit(() -> {
                    var f = new ObjectPublicationFaults();
                    f.action = point -> {
                        if (point.equals("mkdir")) try { barrier.await(10, TimeUnit.SECONDS); }
                        catch (Exception e) { throw new IOException(e); }
                    };
                    try (var store = f.open(root)) {
                        byte[] candidate = bytes(); if (mode.equals("collision")) candidate[0] = (byte) n;
                        try { return store.publishDurably(id(mode.equals("different") ? n + 1 : 1), candidate).name(); }
                        catch (IOException e) { return "failed"; }
                    }
                }));
            }
            var outcomes = List.of(futures.get(0).get(), futures.get(1).get());
            if (mode.equals("same")) assertEquals(Set.of("PUBLISHED_NEW", "ALREADY_PRESENT_EXACT"), new HashSet<>(outcomes));
            else if (mode.equals("collision")) assertEquals(Set.of("PUBLISHED_NEW", "failed"), new HashSet<>(outcomes));
            else assertEquals(List.of("PUBLISHED_NEW", "PUBLISHED_NEW"), outcomes);
        }
        assertEquals(mode.equals("different") ? 2 : 1, names(root.resolve("objects-v1")).size());
    }
    @Test void descriptorStressIncludesAllOwnershipPaths() throws Exception {
        for (int pass = 0; pass < 2; pass++) {
            long before = LinuxVaultBootstrapStorageTest.descriptors();
            for (int i = 0; i < 35; i++) {
                Path dir = Files.createDirectory(root.resolve(pass + "-" + i));
                try (var unused = LinuxV1ObjectPublicationStore.open(dir)) { assertNotNull(unused); assertEquals(List.of(), names(dir)); }
                var f = new ObjectPublicationFaults();
                try (var store = f.open(dir)) {
                    store.publishDurably(id(1), bytes()); store.publishDurably(id(1), bytes());
                    assertThrows(IOException.class, () -> store.publishDurably(id(1), new byte[1024]));
                    f.fail = "stage-sync"; assertThrows(IOException.class, () -> store.publishDurably(id(2), bytes()));
                    f.fail = "post-link-sync"; assertThrows(IOException.class, () -> store.publishDurably(id(2), bytes()));
                    f.fail = ""; Files.move(dir.resolve("objects-v1"), dir.resolve("old")); Files.createDirectory(dir.resolve("objects-v1"));
                    assertThrows(IOException.class, () -> store.publishDurably(id(3), bytes()));
                }
            }
            if (pass == 1) assertEquals(before, LinuxVaultBootstrapStorageTest.descriptors());
        }
    }
}
