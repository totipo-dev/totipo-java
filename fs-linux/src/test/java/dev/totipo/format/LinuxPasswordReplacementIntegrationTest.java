package dev.totipo.format;

import dev.totipo.fs.linux.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultStorageCrashProcess.*;
import static dev.totipo.format.VaultReplacementCrashProcess.NEW_PASSWORD;
import static dev.totipo.format.LinuxVaultLifecycleIntegrationTest.replay;
import static dev.totipo.format.VaultLifecycleResult.Status.*;
import static dev.totipo.format.PasswordChangeStatus.*;

@Timeout(180)
class LinuxPasswordReplacementIntegrationTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path directory(String name) throws IOException { return Files.createDirectory(dir.resolve(name)); }
    static VaultLifecycle changing(VaultBootstrapStorage vault, SecurityMemoryStorage memory, DiscoverySource source, int seed) {
        return new VaultLifecycle(vault, memory, source, bytes -> Arrays.fill(bytes, (byte) seed),
                new VaultBootstrapWriter(), new VaultUnlocker());
    }
    static void create(Path sync, Path local) throws Exception { create(sync, local, ROOT); }
    static void create(Path sync, Path local, byte[] root) throws Exception {
        try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync)) {
            var lifecycle = new VaultLifecycle(vault, memory, new LinuxSecureDiscoverySource(sync), bytes -> {
                if (bytes.length == 32) System.arraycopy(root, 0, bytes, 0, 32); else Arrays.fill(bytes, (byte) 37);
            }, new VaultBootstrapWriter(), new VaultUnlocker());
            try (var result = lifecycle.createNew(PASSWORD)) {
                assertEquals(CREATED_ESTABLISHED, result.status()); assertArrayEquals(root, result.root());
            }
        }
    }
    static byte[] journal(Path local) throws IOException { return Files.readAllBytes(local.resolve("security-memory-v1.bin")); }
    record Remembered(byte[] bytes, byte[] hash, SecurityMemoryJournal.Replay state) {
        static Remembered capture(Path local, SecurityMemoryStorage memory) throws IOException {
            byte[] b = journal(local); return new Remembered(b, SecurityMemoryJournal.hash(b), replay(memory));
        }
        void unchanged(Path local, SecurityMemoryStorage memory) throws IOException {
            byte[] after = journal(local); assertArrayEquals(bytes, after); assertArrayEquals(hash, SecurityMemoryJournal.hash(after));
            var next = replay(memory); assertEquals(SecurityMemoryJournal.Status.CLEAN, next.status());
            assertEquals(LocalEstablishment.Phase.ESTABLISHED, next.establishment().phase());
            assertEquals(state.sequence(), next.sequence()); assertEquals(state.digest(), next.digest());
            assertArrayEquals(state.establishment().binding().bytes(), next.establishment().binding().bytes());
            assertEquals(state.knowledge().records(), next.knowledge().records());
            assertEquals(state.knowledge().continuity(), next.knowledge().continuity());
        }
    }
    static void authenticates(byte[] representation, byte[] password, byte[] root) {
        assertEquals(87, representation.length);
        try (var result = new VaultUnlocker().unlock(representation, password)) {
            assertEquals(VaultUnlockResult.Status.UNLOCKED, result.status()); assertArrayEquals(root, result.root());
            assertArrayEquals(CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding")), result.binding());
        }
    }
    static void atomicActor(Path sync, byte[] bytes) throws IOException {
        Path temp = Files.createTempFile(sync, "external-", ".tmp"); Files.write(temp, bytes);
        Files.move(temp, sync.resolve("vault"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    static Map<String, String> objects(Path sync) throws IOException {
        var result = new TreeMap<String, String>();
        try (var paths = Files.list(sync.resolve("objects-v1"))) {
            for (Path p : paths.toList()) result.put(p.getFileName().toString(),
                    Files.readAttributes(p, BasicFileAttributes.class).fileKey() + ":" + HexFormat.of().formatHex(SecurityMemoryJournal.hash(Files.readAllBytes(p))));
        }
        return result;
    }
    @Test void fullRealRewrapPreservesNonemptyGraphJournalObjectsRootAndBinding() throws Exception {
        Path sync = directory("sync"), local = directory("local");
        var fixture = NioTestFixtures.fixture(NioTestFixtures.TOKEN); byte[] root = fixture.root();
        create(sync, local, root);
        Files.write(Files.createDirectory(sync.resolve("objects-v1")).resolve(fixture.id().filename()), fixture.bytes());
        try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync);
             var opened = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).openConfigured(PASSWORD)) {
            assertEquals(OPENED_ESTABLISHED, opened.status()); assertEquals(1, replay(memory).knowledge().size());
        }
        byte[] old = Files.readAllBytes(sync.resolve("vault"));
        Files.createLink(sync.resolve("historical"), sync.resolve("vault"));
        Object inode = Files.readAttributes(sync.resolve("vault"), BasicFileAttributes.class).fileKey();
        Map<String, String> objects = objects(sync);
        try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync)) {
            var before = Remembered.capture(local, memory);
            var source = new LinuxVaultLifecycleIntegrationTest.ObservedDiscovery(sync, memory);
            assertEquals(SUCCESS, changing(vault, memory, source, 41).changePassword(PASSWORD, NEW_PASSWORD));
            before.unchanged(local, memory); assertEquals(0, source.snapshots); assertEquals(0, source.reads);
            assertEquals(objects, objects(sync));
            byte[] current = Files.readAllBytes(sync.resolve("vault")); authenticates(current, NEW_PASSWORD, root);
            assertFalse(Arrays.equals(old, current));
            assertNotEquals(inode, Files.readAttributes(sync.resolve("vault"), BasicFileAttributes.class).fileKey());
            try (var result = new VaultUnlocker().unlock(current, PASSWORD)) { assertEquals(VaultUnlockResult.Status.AUTHENTICATION_FAILED, result.status()); }
            authenticates(old, PASSWORD, root); authenticates(Files.readAllBytes(sync.resolve("historical")), PASSWORD, root);
        }
        try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync);
             var result = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).openConfigured(NEW_PASSWORD)) {
            assertEquals(OPENED_ESTABLISHED, result.status()); assertArrayEquals(root, result.root());
        }
    }
    @Test void sameAndEmptyPasswordRewrapWithFreshSaltNonce() throws Exception {
        for (byte[] next : List.of(PASSWORD, new byte[0])) {
            Path sync = directory("sync" + next.length), local = directory("local" + next.length); create(sync, local);
            byte[] old = Files.readAllBytes(sync.resolve("vault"));
            try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync)) {
                var before = Remembered.capture(local, memory); var source = new LinuxVaultLifecycleIntegrationTest.ObservedDiscovery(sync, memory);
                assertEquals(SUCCESS, changing(vault, memory, source, 41).changePassword(PASSWORD, next));
                byte[] current = Files.readAllBytes(sync.resolve("vault")); assertFalse(Arrays.equals(old, current));
                assertFalse(Arrays.equals(Arrays.copyOfRange(old, 11, 39), Arrays.copyOfRange(current, 11, 39)));
                authenticates(current, next, ROOT); before.unchanged(local, memory);
                assertEquals(0, source.snapshots); assertEquals(0, source.reads);
            }
        }
    }
    @Test void realFaultStatusMatrixLeavesJournalUnchangedAndReopensActualCanonical() throws Exception {
        for (String failure : List.of("exchange", "post-exchange-sync", "directory-sync", "unlink", "delete", "unsupported")) {
            Path sync = directory("sync-" + failure), local = directory("local-" + failure); create(sync, local);
            var faults = new ReplacementStorageFaults(); faults.fail = failure;
            if (failure.equals("delete")) faults.beforeExchange = () -> Files.delete(sync.resolve("vault"));
            if (failure.equals("unsupported")) faults.unsupportedExchange();
            try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = faults.open(sync)) {
                var before = Remembered.capture(local, memory); var source = new LinuxVaultLifecycleIntegrationTest.ObservedDiscovery(sync, memory);
                assertEquals(failure.equals("unlink") ? SUCCESS : REWRAP_INCOMPLETE,
                        changing(vault, memory, source, 41).changePassword(PASSWORD, NEW_PASSWORD));
                before.unchanged(local, memory); assertEquals(0, source.snapshots); assertEquals(0, source.reads);
                boolean published = List.of("post-exchange-sync", "directory-sync", "unlink").contains(failure);
                if (!failure.equals("delete")) {
                    byte[] password = published ? NEW_PASSWORD : PASSWORD;
                    authenticates(Files.readAllBytes(sync.resolve("vault")), password, ROOT);
                    try (var opened = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).openConfigured(password)) {
                        assertEquals(OPENED_ESTABLISHED, opened.status());
                    }
                } else assertFalse(Files.exists(sync.resolve("vault")));
                if (failure.equals("unlink")) {
                    assertTrue(Files.exists(sync.resolve(faults.linkedName)));
                    authenticates(Files.readAllBytes(sync.resolve(faults.linkedName)), PASSWORD, ROOT);
                }
                before.unchanged(local, memory);
            }
        }
    }
    @Test void coreAcceptsAlternateSameRootRepresentationButRejectsDifferentRootAfterBackend() throws Exception {
        for (boolean same : new boolean[]{true, false}) {
            Path sync = directory("sync" + same), local = directory("local" + same); create(sync, local);
            byte[] otherRoot = ROOT.clone(); if (!same) otherRoot[0] ^= 1;
            byte[] alternate = new VaultBootstrapWriter().encode(NEW_PASSWORD, otherRoot, new byte[16], new byte[12]);
            var faults = new ReplacementStorageFaults(); faults.afterDirectory = () -> atomicActor(sync, alternate);
            try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = faults.open(sync)) {
                var before = Remembered.capture(local, memory); var source = new LinuxVaultLifecycleIntegrationTest.ObservedDiscovery(sync, memory);
                assertEquals(same ? SUCCESS : REWRAP_INCOMPLETE, changing(vault, memory, source, 41).changePassword(PASSWORD, NEW_PASSWORD));
                assertArrayEquals(alternate, Files.readAllBytes(sync.resolve("vault"))); before.unchanged(local, memory);
                assertEquals(0, source.snapshots); assertEquals(0, source.reads);
            }
        }
    }
    @Test void hostileCanonicalSubstitutionMapsToIncompleteWithoutJournalMutation() throws Exception {
        for (String type : List.of("regular", "symlink", "directory")) {
            Path sync = directory("sync-" + type), local = directory("local-" + type); create(sync, local);
            var faults = new ReplacementStorageFaults();
            faults.beforeExchange = () -> {
                Path canonical = sync.resolve("vault"); Files.delete(canonical);
                switch (type) {
                    case "regular" -> Files.write(canonical, new byte[]{9});
                    case "symlink" -> Files.createSymbolicLink(canonical, Path.of("/dev/zero"));
                    case "directory" -> Files.write(Files.createDirectory(canonical).resolve("child"), new byte[]{9});
                }
            };
            try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = faults.open(sync)) {
                var before = Remembered.capture(local, memory); var source = new LinuxVaultLifecycleIntegrationTest.ObservedDiscovery(sync, memory);
                assertEquals(REWRAP_INCOMPLETE, changing(vault, memory, source, 41).changePassword(PASSWORD, NEW_PASSWORD));
                before.unchanged(local, memory); assertEquals(0, source.snapshots); assertEquals(0, source.reads);
                assertEquals(0, faults.unlinks); assertTrue(Files.exists(sync.resolve(faults.linkedName), LinkOption.NOFOLLOW_LINKS));
                authenticates(Files.readAllBytes(sync.resolve("vault")), NEW_PASSWORD, ROOT);
            }
        }
    }
    static void await(CountDownLatch latch) throws IOException {
        try { if (!latch.await(60, TimeUnit.SECONDS)) throw new IOException("barrier timeout"); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
    }
    @Test void twoRealLifecyclesCanBothExchangeAndOnlyFinalPostconditionsDetermineSuccess() throws Exception {
        for (boolean samePassword : new boolean[]{false, true}) {
            Path sync = directory("sync" + samePassword), firstLocal = directory("first" + samePassword), secondLocal = directory("second" + samePassword);
            create(sync, firstLocal);
            try (var memory = LinuxSecurityMemoryStorage.open(secondLocal); var vault = LinuxVaultBootstrapStorage.open(sync);
                 var result = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).configureExisting(PASSWORD)) {
                assertEquals(OPENED_ESTABLISHED, result.status());
            }
            byte[] secondPassword = samePassword ? NEW_PASSWORD : CryptoSupport.ascii("other-new-password");
            var bothStaged = new CountDownLatch(2); var firstDurable = new CountDownLatch(1); var secondDurable = new CountDownLatch(1);
            try (var executor = Executors.newFixedThreadPool(2)) {
                var results = new ArrayList<Future<PasswordChangeStatus>>();
                for (int i = 0; i < 2; i++) {
                    final int index = i; Path local = i == 0 ? firstLocal : secondLocal;
                    results.add(executor.submit(() -> {
                        var faults = new ReplacementStorageFaults();
                        faults.afterLink = () -> {
                            bothStaged.countDown(); await(bothStaged);
                            // Before backend pre-pin: second must observe first's published inode.
                            if (index == 1) await(firstDurable);
                        };
                        faults.afterDirectory = () -> {
                            if (index == 0) { firstDurable.countDown(); await(secondDurable); }
                            else secondDurable.countDown();
                        };
                        try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = faults.open(sync)) {
                            var before = Remembered.capture(local, memory); var source = new LinuxVaultLifecycleIntegrationTest.ObservedDiscovery(sync, memory);
                            var result = changing(vault, memory, source, 41 + index).changePassword(PASSWORD, index == 0 ? NEW_PASSWORD : secondPassword);
                            before.unchanged(local, memory); assertEquals(1, faults.exchanges);
                            assertEquals(0, source.snapshots); assertEquals(0, source.reads); return result;
                        } finally { if (index == 0) firstDurable.countDown(); else secondDurable.countDown(); }
                    }));
                }
                assertEquals(samePassword ? SUCCESS : REWRAP_INCOMPLETE, results.get(0).get());
                assertEquals(SUCCESS, results.get(1).get());
            }
            authenticates(Files.readAllBytes(sync.resolve("vault")), secondPassword, ROOT);
            try (var paths = Files.list(sync)) { assertEquals(List.of("vault"), paths.map(p -> p.getFileName().toString()).toList()); }
        }
    }
    @Test void realRewrapUsesBoundOriginalRootAfterConfiguredPathReplacement() throws Exception {
        Path sync = directory("sync"), local = directory("local"), moved = dir.resolve("moved"); create(sync, local);
        try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync)) {
            var before = Remembered.capture(local, memory); Files.move(sync, moved); Files.createDirectory(sync);
            Files.write(sync.resolve("vault"), new byte[]{9});
            assertEquals(SUCCESS, changing(vault, memory, () -> { throw new AssertionError("discovery"); }, 41).changePassword(PASSWORD, NEW_PASSWORD));
            before.unchanged(local, memory); assertArrayEquals(new byte[]{9}, Files.readAllBytes(sync.resolve("vault")));
            authenticates(Files.readAllBytes(moved.resolve("vault")), NEW_PASSWORD, ROOT);
        }
    }
    void halt(String mode, Path sync, Path local) throws Exception {
        var paths = new ArrayList<String>();
        for (Class<?> type : List.of(VaultReplacementCrashProcess.class, LinuxVaultBootstrapStorage.class,
                VaultBootstrapStorage.class, Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator")))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        var child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny", "-cp", String.join(File.pathSeparator, paths),
                VaultReplacementCrashProcess.class.getName(), mode, sync.toString(), local.toString()).redirectErrorStream(true).start();
        try {
            assertTrue(child.waitFor(60, TimeUnit.SECONDS));
            assertEquals(0, child.exitValue(), new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        } finally { child.destroyForcibly(); }
    }
    @Test void allFiveHaltBoundariesPreserveEstablishedJournalAndOnlyCanonicalIsOpened() throws Exception {
        for (String mode : List.of("stage", "linked", "exchanged", "backend", "full")) {
            Path sync = directory("sync-" + mode), local = directory("local-" + mode); create(sync, local);
            byte[] journal = journal(local), old = Files.readAllBytes(sync.resolve("vault")); halt(mode, sync, local);
            assertArrayEquals(journal, journal(local)); assertArrayEquals(SecurityMemoryJournal.hash(journal), SecurityMemoryJournal.hash(journal(local)));
            boolean exchanged = List.of("exchanged", "backend", "full").contains(mode);
            byte[] password = exchanged ? NEW_PASSWORD : PASSWORD;
            authenticates(Files.readAllBytes(sync.resolve("vault")), password, ROOT);
            List<Path> residue;
            try (var paths = Files.list(sync)) { residue = paths.filter(p -> p.getFileName().toString().startsWith(".totipo-vault-rewrap-")).toList(); }
            assertEquals(List.of("linked", "exchanged").contains(mode) ? 1 : 0, residue.size());
            if (!residue.isEmpty()) authenticates(Files.readAllBytes(residue.getFirst()), exchanged ? PASSWORD : NEW_PASSWORD, ROOT);
            if (!exchanged) assertArrayEquals(old, Files.readAllBytes(sync.resolve("vault")));
            try (var memory = LinuxSecurityMemoryStorage.open(local); var vault = LinuxVaultBootstrapStorage.open(sync)) {
                var before = Remembered.capture(local, memory);
                try (var result = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).openConfigured(password)) {
                    assertEquals(OPENED_ESTABLISHED, result.status()); assertArrayEquals(ROOT, result.root());
                }
                before.unchanged(local, memory);
                // Alternate valid representation is never adopted when canonical disappears.
                if (!residue.isEmpty()) {
                    Files.delete(sync.resolve("vault"));
                    try (var result = lifecycle(vault, memory, new LinuxSecureDiscoverySource(sync)).openConfigured(password)) {
                        assertEquals(CANONICAL_VAULT_ABSENT, result.status());
                    }
                    assertEquals(CURRENT_CANONICAL_ABSENT, changing(vault, memory, () -> { throw new AssertionError("scan"); }, 42).changePassword(password, NEW_PASSWORD));
                    before.unchanged(local, memory);
                }
            }
        }
    }
}
