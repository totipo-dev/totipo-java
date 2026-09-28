package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultStorageCrashProcess.ROOT;
import static dev.totipo.format.LinuxObjectPublicationIntegrationTest.publish;

class LinuxTokenPublicationIntegrationTest {
    @org.junit.jupiter.api.io.TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path sync, local;
    void establish() throws Exception {
        var setup = new LinuxObjectPublicationIntegrationTest(); setup.dir = dir; setup.establish();
        sync = setup.sync; local = setup.local;
    }
    static TokenValue tokenValue() {
        return new TokenValue(1, "Linux", "", new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[]{1}, 1)));
    }
    static InitialTokenPublication.Result token(SecurityMemorySession session, DeviceIdentityResult identity,
            V1ObjectPublicationStore publisher, List<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> ads) {
        return InitialTokenPublication.publish(ROOT, () -> new InitialDeviceAdvertisement.Context(session, DiscoveryState.READY, 0),
                identity, tokenValue(), new byte[8], publisher, ads);
    }
    static TokenPublicationSuccessGate.VerifiedDeviceAdvertisement ad(Path sync, ObjectId id) throws Exception {
        return TokenPublicationSuccessGate.VerifiedDeviceAdvertisement.read(id,
                Files.readAllBytes(sync.resolve("objects-v1").resolve(id.filename())), ROOT, VerificationKeyMaterial.keys());
    }
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void tokenOrdersWithRealRestart(boolean deviceFirst) throws Exception {
        establish();
        byte[] vault = Files.readAllBytes(sync.resolve("vault")), custody = Files.readAllBytes(local.resolve("device-provenance-v1.bin"));
        InitialTokenPublication.Receipt receipt;
        ObjectId deviceId = null;
        byte[] tokenBytes;
        try (var memory = LinuxSecurityMemoryStorage.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var store = NioV1ObjectPublicationStore.open(sync, LinuxDurability.open())) {
            var session = SecurityMemorySession.open(memory);
            try (var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys)) {
                assertEquals(DiscoveryState.READY, DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session).discoveryState());
                var ads = new ArrayList<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement>();
                if (deviceFirst) { deviceId = publish(session, identity, DiscoveryState.READY, store).objectId(); ads.add(ad(sync, deviceId)); }
                var result = token(session, identity, store, ads);
                assertEquals(deviceFirst ? InitialTokenPublication.Status.PUBLISHED_AND_REMEMBERED_SUCCESS_READY
                        : InitialTokenPublication.Status.PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED, result.status());
                receipt = result.receipt();
                tokenBytes = Files.readAllBytes(sync.resolve("objects-v1").resolve(receipt.objectId().filename()));
            }
        }
        try (var memory = LinuxSecurityMemoryStorage.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var store = NioV1ObjectPublicationStore.open(sync, LinuxDurability.open())) {
            var session = SecurityMemorySession.open(memory);
            assertInstanceOf(KnownTokenNode.class, session.knowledge().record(receipt.objectId()));
            try (var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys)) {
                assertEquals(DiscoveryState.READY, DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session).discoveryState());
                assertFalse(TokenPublicationSuccessGate.allows(session, receipt, identity.publicKeyX963(), List.of()));
                if (!deviceFirst) { deviceId = publish(session, identity, DiscoveryState.READY, store).objectId(); }
                assertTrue(TokenPublicationSuccessGate.allows(session, receipt, identity.publicKeyX963(), List.of(ad(sync, deviceId))));
                assertEquals(2, session.knowledge().size());
            }
        }
        assertArrayEquals(tokenBytes, Files.readAllBytes(sync.resolve("objects-v1").resolve(receipt.objectId().filename())));
        assertArrayEquals(vault, Files.readAllBytes(sync.resolve("vault")));
        assertArrayEquals(custody, Files.readAllBytes(local.resolve("device-provenance-v1.bin")));
    }
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void tokenGraphAppendFailureRecovers(boolean deviceFirst) throws Exception {
        establish();
        var faults = new StorageFaults(); ObjectId tokenId;
        try (var memory = faults.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var store = NioV1ObjectPublicationStore.open(sync, LinuxDurability.open())) {
            var session = SecurityMemorySession.open(memory);
            try (var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys)) {
                var ads = new ArrayList<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement>();
                if (deviceFirst) { ads.add(ad(sync, publish(session, identity, DiscoveryState.READY, store).objectId())); }
                faults.failWrite = true;
                var result = token(session, identity, store, ads);
                assertEquals(InitialTokenPublication.Status.KNOWLEDGE_PERSISTENCE_FAILED, result.status());
                assertNull(result.receipt()); assertTrue(session.knowledge().knowledgePersistenceBlocked());
                try (var files = Files.list(sync.resolve("objects-v1"))) {
                    tokenId = files.map(p -> ObjectId.fromFilename(p.getFileName().toString()))
                            .filter(id -> session.knowledge().record(id) == null).findFirst().orElseThrow();
                }
            }
        }
        try (var memory = LinuxSecurityMemoryStorage.open(local)) {
            var session = SecurityMemorySession.open(memory);
            assertNull(session.knowledge().record(tokenId));
            assertEquals(DiscoveryState.READY, DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session).discoveryState());
            assertInstanceOf(KnownTokenNode.class, session.knowledge().record(tokenId));
            assertEquals(session.knowledge().record(tokenId), SecurityMemorySession.open(memory).knowledge().record(tokenId));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"pregraph", "pending"})
    void processHaltAndRecoverSameToken(String mode) throws Exception {
        establish();
        byte[] vault = Files.readAllBytes(sync.resolve("vault")), custody = Files.readAllBytes(local.resolve("device-provenance-v1.bin"));
        var paths = new ArrayList<String>();
        for (Class<?> type : List.of(TokenPublicationCrashProcess.class, LinuxDurability.class, NioV1ObjectPublicationStore.class, ObjectId.class)) {
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        }
        var process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny", "-cp", String.join(java.io.File.pathSeparator, paths),
                TokenPublicationCrashProcess.class.getName(), mode, sync.toString(), local.toString()).redirectErrorStream(true).start();
        String output;
        try {
            assertTrue(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS));
            output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            assertEquals(0, process.exitValue(), output);
        } finally { process.destroyForcibly(); }
        var id = ObjectId.fromFilename(output);
        byte[] bytes = Files.readAllBytes(sync.resolve("objects-v1").resolve(id.filename()));
        try (var memory = LinuxSecurityMemoryStorage.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var store = NioV1ObjectPublicationStore.open(sync, LinuxDurability.open())) {
            var session = SecurityMemorySession.open(memory);
            assertEquals(mode.equals("pending"), session.knowledge().record(id) != null);
            assertEquals(DiscoveryState.READY, DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session).discoveryState());
            var node = (KnownTokenNode) session.knowledge().record(id);
            var receipt = new InitialTokenPublication.Receipt(node.tokenId(), id, node.authorDeviceId());
            try (var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys)) {
                assertFalse(TokenPublicationSuccessGate.allows(session, receipt, identity.publicKeyX963(), List.of()));
                var device = publish(session, identity, DiscoveryState.READY, store);
                assertTrue(TokenPublicationSuccessGate.allows(session, receipt, identity.publicKeyX963(), List.of(ad(sync, device.objectId()))));
            }
        }
        assertArrayEquals(bytes, Files.readAllBytes(sync.resolve("objects-v1").resolve(id.filename())));
        assertArrayEquals(vault, Files.readAllBytes(sync.resolve("vault")));
        assertArrayEquals(custody, Files.readAllBytes(local.resolve("device-provenance-v1.bin")));
    }
}
