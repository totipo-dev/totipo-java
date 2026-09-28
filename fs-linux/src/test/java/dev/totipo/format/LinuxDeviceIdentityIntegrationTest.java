package dev.totipo.format;

import dev.totipo.fs.linux.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DeviceIdentityResult.Status.*;
import static dev.totipo.format.LinuxPasswordReplacementIntegrationTest.*;
import static dev.totipo.format.LinuxVaultLifecycleIntegrationTest.replay;
import static dev.totipo.format.VaultStorageCrashProcess.PASSWORD;
import static dev.totipo.format.VaultReplacementCrashProcess.NEW_PASSWORD;

@Timeout(180)
class LinuxDeviceIdentityIntegrationTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    static final String NAME = "device-provenance-v1.bin";
    Path directory(String name) throws IOException { return Files.createDirectory(dir.resolve(name)); }
    static void verify(DeviceIdentityResult result) throws Exception {
        assertArrayEquals(P256.deviceId(result.publicKeyX963()), result.deviceId());
        byte[] message = CryptoSupport.ascii("restart identity continuity");
        assertTrue(P256.verify(result.publicKeyX963(), message, result.signSha256Ecdsa(message)));
    }
    static byte[] keyHash(Path local) throws IOException { return SecurityMemoryJournal.hash(Files.readAllBytes(local.resolve(NAME))); }
    @Test void realCreateRestartRewrapContinuityAndAllStorageInvariants() throws Exception {
        Path sync = directory("sync"), local = directory("local"); create(sync, local);
        Files.write(Files.createDirectory(sync.resolve("objects-v1")).resolve("sentinel"), new byte[]{7, 8, 9});
        byte[] vaultBefore = Files.readAllBytes(sync.resolve("vault")), journalBefore = journal(local);
        var objectsBefore = objects(sync);
        byte[] publicKey, id, binding, hash;
        try (var memory = LinuxSecurityMemoryStorage.open(local); var store = LinuxDeviceProvenanceKeyStore.open(local)) {
            assertEquals(SecurityMemoryJournal.Status.CLEAN, replay(memory).status());
            assertEquals(LocalEstablishment.Phase.ESTABLISHED, replay(memory).establishment().phase());
            try (var absent = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) { assertEquals(ABSENT, absent.status()); }
            try (var result = DeviceIdentityLifecycle.createNew(replay(memory), store)) {
                assertEquals(CREATED_BOUND, result.status()); verify(result);
                publicKey = result.publicKeyX963(); id = result.deviceId(); binding = result.vaultBinding();
            }
            hash = keyHash(local);
            assertArrayEquals(journalBefore, journal(local));
            assertArrayEquals(vaultBefore, Files.readAllBytes(sync.resolve("vault"))); assertEquals(objectsBefore, objects(sync));
        }
        try (var memory = LinuxSecurityMemoryStorage.open(local); var store = LinuxDeviceProvenanceKeyStore.open(local);
             var loaded = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) {
            assertEquals(AVAILABLE_BOUND, loaded.status()); assertArrayEquals(id, loaded.deviceId());
            assertArrayEquals(publicKey, loaded.publicKeyX963()); assertArrayEquals(binding, loaded.vaultBinding()); verify(loaded);
            assertArrayEquals(journalBefore, journal(local)); assertArrayEquals(hash, keyHash(local));
            try (var vault = LinuxVaultBootstrapStorage.open(sync)) {
                assertEquals(PasswordChangeStatus.SUCCESS,
                        changing(vault, memory, new NioDiscoverySource(sync), 41).changePassword(PASSWORD, NEW_PASSWORD));
            }
            assertArrayEquals(journalBefore, journal(local)); assertEquals(objectsBefore, objects(sync)); assertArrayEquals(hash, keyHash(local));
            assertTrue(SecurityMemorySession.open(memory).markUnknown());
            byte[] afterContinuity = journal(local);
            try (var again = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) { assertEquals(AVAILABLE_BOUND, again.status()); verify(again); }
            assertArrayEquals(afterContinuity, journal(local)); assertArrayEquals(hash, keyHash(local));
        }
        try (var memory = LinuxSecurityMemoryStorage.open(local); var store = LinuxDeviceProvenanceKeyStore.open(local);
             var loaded = DeviceIdentityLifecycle.loadExisting(replay(memory), store);
             var unlocked = new VaultUnlocker().unlock(Files.readAllBytes(sync.resolve("vault")), NEW_PASSWORD)) {
            assertArrayEquals(binding, unlocked.binding()); assertArrayEquals(binding, loaded.vaultBinding());
            assertArrayEquals(id, loaded.deviceId()); assertArrayEquals(publicKey, loaded.publicKeyX963()); verify(loaded);
            assertArrayEquals(hash, keyHash(local));
        }
    }
    @Test void differentEstablishedBindingStopsBeforeSigningAndLeavesRecordUnchanged() throws Exception {
        Path a = directory("a"), b = directory("b");
        byte[] first = new byte[32], second = new byte[32]; second[0] = 1;
        try (var memory = LinuxSecurityMemoryStorage.open(b)) {
            assertTrue(SecurityMemorySession.initializeNew(memory).establishFirstOpen(second));
        }
        try (var store = LinuxDeviceProvenanceKeyStore.open(a); var key = store.createDurably(first)) { assertArrayEquals(first, key.vaultBinding()); }
        byte[] hash = keyHash(a), journalBefore = journal(b); int[] signs = {0};
        try (var memory = LinuxSecurityMemoryStorage.open(b); var backend = LinuxDeviceProvenanceKeyStore.open(a)) {
            var counted = new DeviceProvenanceKeyStore() {
                @Override public DeviceProvenanceKey openExisting() throws IOException, GeneralSecurityException {
                    var key = backend.openExisting();
                    return new DeviceProvenanceKey() {
                        public byte[] vaultBinding() { return key.vaultBinding(); }
                        public byte[] publicKeyX963() { return key.publicKeyX963(); }
                        public byte[] signSha256Ecdsa(byte[] message) throws GeneralSecurityException { signs[0]++; return key.signSha256Ecdsa(message); }
                        public void close() { key.close(); }
                    };
                }
                public DeviceProvenanceKey createDurably(byte[] binding) { throw new AssertionError(); }
                public void close() {}
            };
            try (var result = DeviceIdentityLifecycle.loadExisting(replay(memory), counted)) { assertEquals(KEY_BINDING_MISMATCH, result.status()); }
            assertEquals(0, signs[0]); assertArrayEquals(hash, keyHash(a)); assertArrayEquals(journalBefore, journal(b));
        }
    }
    @Test void corruptDerAndMismatchedPublicMetadataAreMaterialInvalidWithoutRepair() throws Exception {
        Path local = directory("local"); byte[] good;
        try (var memory = LinuxSecurityMemoryStorage.open(local); var store = LinuxDeviceProvenanceKeyStore.open(local)) {
            assertTrue(SecurityMemorySession.initializeNew(memory).establishFirstOpen(new byte[32]));
            try (var created = DeviceIdentityLifecycle.createNew(replay(memory), store)) { assertEquals(CREATED_BOUND, created.status()); }
            good = Files.readAllBytes(local.resolve(NAME));
            var generator = KeyPairGenerator.getInstance("EC"); generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            byte[] otherPublic = DeviceProvenancePublicKey.encodeX963((java.security.interfaces.ECPublicKey) generator.generateKeyPair().getPublic());
            for (boolean der : List.of(true, false)) {
                byte[] bad = good.clone();
                if (der) bad[111] = 0; else System.arraycopy(otherPublic, 0, bad, 44, 65);
                Files.write(local.resolve(NAME), bad);
                if (!der) try (var parseable = store.openExisting()) { assertArrayEquals(otherPublic, parseable.publicKeyX963()); }
                try (var result = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) { assertEquals(KEY_MATERIAL_INVALID, result.status()); }
                assertArrayEquals(bad, Files.readAllBytes(local.resolve(NAME)));
            }
        }
    }
    @Test void lifecycleFaultsAndEexistRequireExplicitLoad() throws Exception {
        for (String failure : List.of("temporary", "write", "initial-sync", "staged-read", "validation", "link", "post-link-sync", "directory-sync", "persisted-reopen", "eexist")) {
            Path local = directory(failure); var faults = new DeviceKeyFaults(); faults.fail = failure;
            byte[][] winner = {null};
            if (failure.equals("eexist")) faults.action = name -> {
                if (name.equals("link")) try (var other = LinuxDeviceProvenanceKeyStore.open(local); var key = other.createDurably(new byte[32])) {
                    assertArrayEquals(new byte[32], key.vaultBinding());
                    winner[0] = Files.readAllBytes(local.resolve(NAME));
                } catch (GeneralSecurityException e) { throw new IOException(e); }
            };
            try (var memory = LinuxSecurityMemoryStorage.open(local); var store = faults.open(local)) {
                assertTrue(SecurityMemorySession.initializeNew(memory).establishFirstOpen(new byte[32]));
                byte[] before = journal(local);
                try (var result = DeviceIdentityLifecycle.createNew(replay(memory), store)) { assertEquals(KEY_CREATION_INCOMPLETE, result.status()); }
                assertEquals(1, faults.generations); assertArrayEquals(before, journal(local));
                if (winner[0] != null) assertArrayEquals(winner[0], Files.readAllBytes(local.resolve(NAME)));
                try (var fresh = LinuxDeviceProvenanceKeyStore.open(local); var result = DeviceIdentityLifecycle.loadExisting(replay(memory), fresh)) {
                    boolean published = List.of("post-link-sync", "directory-sync", "persisted-reopen", "eexist").contains(failure);
                    assertEquals(published ? AVAILABLE_BOUND : ABSENT, result.status()); if (published) verify(result);
                }
            }
        }
    }
    Process child(String mode, Path local) throws Exception {
        var paths = new ArrayList<String>();
        for (Class<?> type : List.of(DeviceKeyCrashProcess.class, LinuxDeviceProvenanceKeyStore.class, DeviceProvenanceKeyStore.class))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        return new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny", "-cp", String.join(File.pathSeparator, paths),
                DeviceKeyCrashProcess.class.getName(), mode, local.toString()).redirectErrorStream(true).start();
    }
    @Test void fourAbruptHaltBoundaries() throws Exception {
        for (String mode : List.of("staged", "linked", "returned", "lifecycle")) {
            Path local = directory(mode);
            if (mode.equals("lifecycle")) try (var memory = LinuxSecurityMemoryStorage.open(local)) {
                assertTrue(SecurityMemorySession.initializeNew(memory).establishFirstOpen(new byte[32]));
            }
            var process = child(mode, local); String output;
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS)); output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
                assertEquals(0, process.exitValue(), output);
            } finally { process.destroyForcibly(); }
            try (var store = LinuxDeviceProvenanceKeyStore.open(local); var key = store.openExisting()) {
                if (mode.equals("staged")) {
                    assertNull(key); try (var entries = Files.list(local)) { assertTrue(entries.allMatch(p -> p.getFileName().toString().startsWith(".totipo-device-key-"))); }
                } else {
                    assertNotNull(key); assertArrayEquals(new byte[32], key.vaultBinding());
                    byte[] publicKey = key.publicKeyX963(), message = {7};
                    assertTrue(P256.verify(publicKey, message, key.signSha256Ecdsa(message)));
                    if (mode.equals("returned")) assertEquals(output, HexFormat.of().formatHex(publicKey));
                    if (mode.equals("lifecycle")) try (var memory = LinuxSecurityMemoryStorage.open(local);
                         var result = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) {
                        assertEquals(AVAILABLE_BOUND, result.status()); assertEquals(output, HexFormat.of().formatHex(result.deviceId())); verify(result);
                    }
                }
            }
        }
    }
    @Test void coordinatedProcessesHaveOneWinnerAndStableReloadedIdentity() throws Exception {
        Path local = directory("race"); var a = child("race", local); var b = child("race", local);
        try (var ar = a.inputReader(); var br = b.inputReader()) {
            assertEquals("READY", ar.readLine()); assertEquals("READY", br.readLine());
            a.getOutputStream().write('G'); a.getOutputStream().flush(); b.getOutputStream().write('G'); b.getOutputStream().flush();
            assertTrue(a.waitFor(30, TimeUnit.SECONDS)); assertTrue(b.waitFor(30, TimeUnit.SECONDS));
            assertEquals(Set.of(0, 3), Set.of(a.exitValue(), b.exitValue()));
            String publicHex = a.exitValue() == 0 ? ar.readLine() : br.readLine();
            byte[] hash = keyHash(local);
            var reload = child("load", local);
            try {
                assertTrue(reload.waitFor(30, TimeUnit.SECONDS)); assertEquals(0, reload.exitValue());
                assertEquals(HexFormat.of().formatHex(P256.deviceId(HexFormat.of().parseHex(publicHex))), reload.inputReader().readLine());
            } finally { reload.destroyForcibly(); }
            for (int i = 0; i < 2; i++) try (var store = LinuxDeviceProvenanceKeyStore.open(local); var key = store.openExisting()) {
                assertEquals(publicHex, HexFormat.of().formatHex(key.publicKeyX963()));
                byte[] message = {1}; assertTrue(P256.verify(key.publicKeyX963(), message, key.signSha256Ecdsa(message)));
                assertArrayEquals(hash, keyHash(local));
            }
            try (var entries = Files.list(local)) { assertEquals(List.of(NAME), entries.map(p -> p.getFileName().toString()).filter(n -> !n.startsWith(".totipo-device-key-")).toList()); }
        } finally { a.destroyForcibly(); b.destroyForcibly(); }
    }
}
