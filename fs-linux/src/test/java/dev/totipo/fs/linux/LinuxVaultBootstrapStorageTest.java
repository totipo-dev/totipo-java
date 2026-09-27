package dev.totipo.fs.linux;

import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(30)
class LinuxVaultBootstrapStorageTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path root;
    Path canonical() { return root.resolve("vault"); }
    static byte[] candidate() { byte[] b = new byte[87]; new Random(7).nextBytes(b); return b; }
    List<String> names() throws IOException {
        try (var paths = Files.list(root)) { return paths.map(p -> p.getFileName().toString()).sorted().toList(); }
    }
    @Test void unnamedExactDurableStagingAndHardLinkIdentity() throws Exception {
        var faults = new VaultStorageFaults(); faults.writeLimit = 7;
        byte[] original = candidate(), caller = original.clone();
        try (var storage = faults.open(root); var stage = storage.stageInitial(caller)) {
            Arrays.fill(caller, (byte) 0);
            assertEquals(List.of(), names()); assertNull(storage.openCanonicalRead());
            assertEquals(1, faults.stageSyncs); assertFalse(faults.events.contains("directory-sync"));
            for (int i = 0; i < 2; i++) try (var read = stage.openRead()) {
                assertArrayEquals(Arrays.copyOf(original, 3), read.readNBytes(3));
                assertArrayEquals(Arrays.copyOfRange(original, 3, 87), read.readAllBytes());
            }
            stage.installInitialDurably();
            assertEquals(List.of("vault"), names()); assertEquals(87, Files.size(canonical()));
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(canonical()));
            var libc = new LinuxLibc();
            try (var pin = libc.open(canonical().toString(), LinuxAbi.PIN)) {
                assertEquals(faults.stagedIdentity, libc.stat(pin));
            }
            assertEquals(List.of("stage-sync", "link", "post-link-sync", "directory-sync"),
                    faults.events.stream().filter(s -> !s.equals("write") && !s.equals("temporary")).toList());
            assertThrows(IOException.class, stage::installInitialDurably);
            try (var read = storage.openCanonicalRead()) { assertArrayEquals(original, read.readAllBytes()); }
        }
        assertArrayEquals(original, Files.readAllBytes(canonical()));
    }
    @Test void closeOwnershipAndNoResidue() throws Exception {
        var storage = LinuxVaultBootstrapStorage.open(root); var stage = storage.stageInitial(candidate());
        stage.close(); stage.close();
        assertThrows(IOException.class, stage::openRead); assertThrows(IOException.class, stage::installInitialDurably);
        assertEquals(List.of(), names());
        var abandoned = storage.stageInitial(candidate()); storage.close(); storage.close(); abandoned.close();
        assertThrows(IOException.class, abandoned::openRead);
        assertThrows(IOException.class, abandoned::installInitialDurably);
        assertThrows(IOException.class, storage::openCanonicalRead);
        assertThrows(IOException.class, () -> storage.stageInitial(candidate()));
        assertEquals(List.of(), names());
    }
    @Test void callerMutationAfterCopyCannotChangeStagedOrInstalledBytes() throws Exception {
        byte[] original = new byte[32771]; new Random(19).nextBytes(original);
        byte[] caller = original.clone();
        var copied = new CountDownLatch(1); var resume = new CountDownLatch(1);
        var faults = new VaultStorageFaults(); faults.writeLimit = 4096;
        // The existing temporary-open hook runs after the copy, before any native staging I/O.
        faults.beforeStage = () -> {
            copied.countDown();
            try { assertTrue(resume.await(10, TimeUnit.SECONDS)); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
        };
        try (var executor = Executors.newSingleThreadExecutor()) {
            var result = executor.submit(() -> {
                try (var storage = faults.open(root); var stage = storage.stageInitial(caller)) {
                    try (var read = stage.openRead()) {
                        byte[] staged = read.readAllBytes();
                        assertArrayEquals(original, staged); assertFalse(Arrays.equals(caller, staged));
                    }
                    stage.installInitialDurably();
                    try (var read = storage.openCanonicalRead()) {
                        byte[] installed = read.readAllBytes();
                        assertArrayEquals(original, installed); assertFalse(Arrays.equals(caller, installed));
                    }
                }
                return null;
            });
            try {
                assertTrue(copied.await(10, TimeUnit.SECONDS));
                for (int i = 0; i < caller.length; i++) caller[i] ^= (byte) 0xff;
            } finally { resume.countDown(); }
            result.get(10, TimeUnit.SECONDS);
        }
    }
    @Test void ownedCopyIsWipedAfterSuccessWriteFailureAndFsyncFailure() throws Exception {
        for (String failure : List.of("none", "write", "fsync")) {
            var operations = new LinuxVaultBootstrapStorage.Operations() {
                java.nio.ByteBuffer observed;
                @Override int write(LinuxLibc libc, LinuxFd fd, java.nio.ByteBuffer bytes) throws IOException {
                    // Retain a test-only view through the existing seam; production retains no copy.
                    observed = bytes.duplicate();
                    if (failure.equals("write")) throw new IOException("injected write");
                    return super.write(libc, fd, bytes);
                }
                @Override void syncStage(LinuxLibc libc, LinuxFd fd) throws IOException {
                    if (failure.equals("fsync")) throw new IOException("injected fsync");
                    super.syncStage(libc, fd);
                }
            };
            byte[] caller = candidate();
            try (var storage = LinuxVaultBootstrapStorage.open(root, operations)) {
                if (failure.equals("none")) {
                    try (var stage = storage.stageInitial(caller); var read = stage.openRead()) {
                        assertArrayEquals(candidate(), read.readAllBytes());
                    }
                } else assertThrows(IOException.class, () -> storage.stageInitial(caller));
                assertArrayEquals(candidate(), caller);
                byte[] observed = new byte[operations.observed.remaining()]; operations.observed.get(observed);
                assertArrayEquals(new byte[caller.length], observed);
            }
        }
    }
    @Test void opaqueEmptyAndMultiBufferCandidatesAreExact() throws Exception {
        for (int length : new int[]{0, 32771}) {
            byte[] bytes = new byte[length]; new Random(length).nextBytes(bytes);
            try (var storage = LinuxVaultBootstrapStorage.open(root); var stage = storage.stageInitial(bytes)) {
                try (var read = stage.openRead()) { assertArrayEquals(bytes, read.readAllBytes()); }
                stage.installInitialDurably(); assertEquals(length, Files.size(canonical()));
                try (var read = storage.openCanonicalRead()) { assertArrayEquals(bytes, read.readAllBytes()); }
            }
            Files.delete(canonical());
        }
    }
    @Test void inaccessibleCanonicalIsNotAbsenceAndExistingModeIsNotChanged() throws Exception {
        Files.write(canonical(), candidate());
        try (var storage = LinuxVaultBootstrapStorage.open(root)) {
            Files.setPosixFilePermissions(canonical(), PosixFilePermissions.fromString("rw-r--r--"));
            try (var read = storage.openCanonicalRead()) { assertArrayEquals(candidate(), read.readAllBytes()); }
            assertEquals(PosixFilePermissions.fromString("rw-r--r--"), Files.getPosixFilePermissions(canonical()));
            Files.setPosixFilePermissions(canonical(), Set.of());
            // Under elevated test runners DAC may be bypassed; normal unprivileged execution exercises EACCES.
            if (!Files.isReadable(canonical())) assertThrows(IOException.class, storage::openCanonicalRead);
        } finally { Files.setPosixFilePermissions(canonical(), PosixFilePermissions.fromString("rw-------")); }
    }
    @Test void rootContractAndJavaNativeIdentity() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> LinuxVaultBootstrapStorage.open(Path.of("relative")));
        assertThrows(IOException.class, () -> LinuxVaultBootstrapStorage.open(root.resolve("missing")));
        Path file = Files.write(root.resolve("file"), new byte[0]);
        assertThrows(IOException.class, () -> LinuxVaultBootstrapStorage.open(file));
        Path link = Files.createSymbolicLink(root.resolve("link"), root);
        assertThrows(IOException.class, () -> LinuxVaultBootstrapStorage.open(link));
        Path raw = Path.of(java.net.URI.create(root.toUri().toASCIIString() + "%ff")); Files.createDirectory(raw);
        assertThrows(IOException.class, () -> LinuxVaultBootstrapStorage.open(raw));
        for (String name : List.of("with spaces", "caf\u00e9", "lock-\ud83d\udd10")) {
            try (var storage = LinuxVaultBootstrapStorage.open(Files.createDirectory(root.resolve(name)))) {
                assertNull(storage.openCanonicalRead());
            }
        }
        try (var zip = FileSystems.newFileSystem(java.net.URI.create("jar:" + root.resolve("x.zip").toUri()), Map.of("create", "true"))) {
            assertThrows(IllegalArgumentException.class, () -> LinuxVaultBootstrapStorage.open(zip.getPath("/")));
        }
    }
    @Test void canonicalOnlyAndNoMetadataCache() throws Exception {
        for (String name : List.of("vault.tmp", "vault.backup", "vault.sync-conflict", "VAULT"))
            Files.write(root.resolve(name), candidate());
        try (var storage = LinuxVaultBootstrapStorage.open(root)) {
            assertNull(storage.openCanonicalRead());
            Files.write(canonical(), candidate());
            var time = Files.getLastModifiedTime(canonical());
            try (var read = storage.openCanonicalRead()) { assertArrayEquals(candidate(), read.readAllBytes()); }
            byte[] next = candidate(); next[40] ^= 1; Files.write(canonical(), next); Files.setLastModifiedTime(canonical(), time);
            try (var read = storage.openCanonicalRead()) { assertArrayEquals(next, read.readAllBytes()); }
        }
    }
    @Test void pinnedReadSurvivesPathReplacementAndStorageClose() throws Exception {
        Files.write(canonical(), candidate());
        var storage = LinuxVaultBootstrapStorage.open(root);
        try (var read = storage.openCanonicalRead()) {
            Files.move(canonical(), root.resolve("old")); Files.write(canonical(), new byte[]{9});
            try (var next = storage.openCanonicalRead()) { assertArrayEquals(new byte[]{9}, next.readAllBytes()); }
            storage.close(); assertArrayEquals(candidate(), read.readAllBytes());
        } finally { storage.close(); }
    }
    @Test void rootRenameKeepsReadsAndPublicationBound() throws Exception {
        Path configured = Files.createDirectory(root.resolve("configured")), moved = root.resolve("moved");
        try (var storage = LinuxVaultBootstrapStorage.open(configured)) {
            Files.move(configured, moved); Files.createDirectory(configured);
            try (var stage = storage.stageInitial(candidate())) { stage.installInitialDurably(); }
            assertArrayEquals(candidate(), Files.readAllBytes(moved.resolve("vault")));
            assertFalse(Files.exists(configured.resolve("vault")));
            Files.write(configured.resolve("vault"), new byte[]{8});
            try (var read = storage.openCanonicalRead()) { assertArrayEquals(candidate(), read.readAllBytes()); }
            try (var next = LinuxVaultBootstrapStorage.open(configured); var read = next.openCanonicalRead()) {
                assertArrayEquals(new byte[]{8}, read.readAllBytes());
            }
        }
    }
    @Test void specialCanonicalObjectsNeverReadOrReplace() throws Exception {
        // Socket path must remain below the AF_UNIX pathname limit.
        Path shortRoot = Files.createTempDirectory("vault-special-");
        try {
            Path path = shortRoot.resolve("vault");
            try (var storage = LinuxVaultBootstrapStorage.open(shortRoot)) {
                for (String form : List.of("symlink", "directory", "fifo", "socket")) {
                    try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
                        switch (form) {
                            case "symlink" -> Files.createSymbolicLink(path, Path.of("/dev/zero"));
                            case "directory" -> Files.createDirectory(path);
                            case "fifo" -> LinuxSecureSourceTest.fifo(path);
                            case "socket" -> socket.bind(UnixDomainSocketAddress.of(path));
                            default -> throw new AssertionError();
                        }
                        assertThrows(IOException.class, storage::openCanonicalRead);
                        try (var stage = storage.stageInitial(candidate())) {
                            var error = assertThrows(LinuxLibc.NativeFailure.class, stage::installInitialDurably);
                            assertEquals(LinuxAbi.EEXIST, error.errno);
                        }
                        assertTrue(Files.exists(path, LinkOption.NOFOLLOW_LINKS)); Files.delete(path);
                    }
                }
            }
        } finally { Files.deleteIfExists(shortRoot.resolve("vault")); Files.delete(shortRoot); }
    }
    @Test void exactCollisionPreservesCanonicalAndDiscardsCandidate() throws Exception {
        try (var storage = LinuxVaultBootstrapStorage.open(root); var stage = storage.stageInitial(candidate())) {
            Files.write(canonical(), new byte[]{1, 2, 3});
            assertEquals(LinuxAbi.EEXIST, assertThrows(LinuxLibc.NativeFailure.class, stage::installInitialDurably).errno);
            assertThrows(IOException.class, stage::installInitialDurably);
        }
        assertArrayEquals(new byte[]{1, 2, 3}, Files.readAllBytes(canonical())); assertEquals(List.of("vault"), names());
    }
    @Test void faultsPreserveActualOutcomeAndDoNotRetry() throws Exception {
        for (String fail : List.of("write", "partial-write", "zero", "stage-sync", "link", "post-link-sync", "directory-sync")) {
            Path dir = Files.createDirectory(root.resolve(fail)); var faults = new VaultStorageFaults(); faults.fail = fail;
            faults.writeLimit = 7;
            try (var storage = faults.open(dir)) {
                if (List.of("write", "partial-write", "zero", "stage-sync").contains(fail)) {
                    assertThrows(IOException.class, () -> storage.stageInitial(candidate()));
                    assertFalse(faults.events.contains("link"));
                } else try (var stage = storage.stageInitial(candidate())) {
                    assertThrows(IOException.class, stage::installInitialDurably);
                    assertThrows(IOException.class, stage::installInitialDurably);
                }
            }
            boolean linked = fail.equals("post-link-sync") || fail.equals("directory-sync");
            try (var listing = Files.list(dir)) { assertEquals(linked ? 1 : 0, listing.count()); }
            if (linked) assertArrayEquals(candidate(), Files.readAllBytes(dir.resolve("vault")));
            if (fail.equals("post-link-sync")) assertFalse(faults.events.contains("directory-sync"));
        }
        for (int errno : new int[]{LinuxAbi.EOPNOTSUPP, 21, LinuxAbi.EINTR}) {
            var faults = new VaultStorageFaults(); faults.temporaryErrno = errno;
            try (var storage = faults.open(root)) {
                assertThrows(IOException.class, () -> storage.stageInitial(candidate()));
                assertEquals(List.of("temporary"), faults.events);
            }
        }
        assertFalse(Files.exists(canonical()));
    }
    @Test void concurrentCreatorsUseKernelExclusion() throws Exception {
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                final byte value = (byte) i;
                results.add(executor.submit(() -> {
                    try (var storage = LinuxVaultBootstrapStorage.open(root); var stage = storage.stageInitial(new byte[]{value})) {
                        barrier.await(10, TimeUnit.SECONDS);
                        try { stage.installInitialDurably(); return true; }
                        catch (LinuxLibc.NativeFailure e) { assertEquals(LinuxAbi.EEXIST, e.errno); return false; }
                    }
                }));
            }
            assertNotEquals(results.get(0).get(), results.get(1).get());
        }
        assertEquals(1, Files.size(canonical())); assertEquals(List.of("vault"), names());
    }
    static long descriptors() throws IOException { try (var fds = Files.list(Path.of("/proc/self/fd"))) { return fds.count(); } }
    @Test void descriptorStressAcrossSuccessCollisionAndFaultPaths() throws Exception {
        // Warm native/JDK paths before measuring steady-state ownership.
        for (int pass = 0; pass < 2; pass++) {
            long before = descriptors();
            for (int i = 0; i < 80; i++) {
                var faults = new VaultStorageFaults();
                try (var storage = faults.open(root)) {
                    assertNull(storage.openCanonicalRead());
                    try (var stage = storage.stageInitial(candidate()); var read = stage.openRead()) { assertEquals(87, read.readAllBytes().length); }
                    try (var stage = storage.stageInitial(candidate())) { stage.installInitialDurably(); }
                    try (var read = storage.openCanonicalRead()) { assertEquals(87, read.readAllBytes().length); }
                    try (var stage = storage.stageInitial(candidate())) { assertThrows(IOException.class, stage::installInitialDurably); }
                    faults.fail = "write"; assertThrows(IOException.class, () -> storage.stageInitial(candidate()));
                }
                Files.delete(canonical());
            }
            if (pass > 0) assertEquals(before, descriptors());
        }
    }
}
