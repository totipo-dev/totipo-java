package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.LinuxDurability;

import dev.totipo.platform.linux.*;
import java.io.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialDeviceAdvertisement.Status.*;
import static dev.totipo.format.VaultStorageCrashProcess.ROOT;
import static dev.totipo.format.LinuxPasswordReplacementIntegrationTest.create;

@Timeout(180)
class LinuxObjectPublicationIntegrationTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path sync, local;
    void establish() throws Exception {
        sync = Files.createDirectory(dir.resolve("sync")); local = Files.createDirectory(dir.resolve("local"));
        create(sync, local);
        try (var memory = LinuxSecurityMemoryStorage.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var identity = DeviceIdentityLifecycle.createNew(SecurityMemorySession.open(memory).head(), keys)) {
            assertEquals(DeviceIdentityResult.Status.CREATED_BOUND, identity.status());
        }
    }
    static KnownDeviceNode authenticate(Path sync, ObjectId id, byte[] root, byte[] publicKey) throws Exception {
        assertTrue(id.filename().matches("[0-9a-f]{64}"));
        byte[] bytes = Files.readAllBytes(sync.resolve("objects-v1").resolve(id.filename())); assertEquals(1024, bytes.length);
        var read = EnvelopeReader.open(id.filename(), bytes, root);
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE, read.status());
        assertTrue(DeviceWriter.matches(read.plaintext(), publicKey, DeviceWriter.displayName("Linux device"), new byte[8], List.of()));
        var assertion = AssertionValidator.validate(read);
        assertEquals(AssertionValidator.Status.ASSERTION_VALID, assertion.status());
        assertEquals(ProvenanceStatus.VERIFIED, ProvenanceEvaluator.evaluate(assertion.object(), root, VerificationKeyMaterial.available(List.of())));
        return (KnownDeviceNode) AuthenticatedObservation.supported(assertion.object()).record();
    }
    static InitialDeviceAdvertisement.Result publish(SecurityMemorySession session, DeviceIdentityResult identity,
                                                      DiscoveryState state, V1ObjectPublicationStore publisher) {
        return InitialDeviceAdvertisement.publish(ROOT, () -> new InitialDeviceAdvertisement.Context(session, state, 0),
                identity, "Linux device", new byte[8], publisher);
    }
    static final class CountedKey implements DeviceProvenanceKey {
        final DeviceProvenanceKey delegate; int signs;
        CountedKey(DeviceProvenanceKey delegate) { this.delegate = delegate; }
        public byte[] vaultBinding() { return delegate.vaultBinding(); }
        public byte[] publicKeyX963() { return delegate.publicKeyX963(); }
        public byte[] signSha256Ecdsa(byte[] message) throws GeneralSecurityException { signs++; return delegate.signSha256Ecdsa(message); }
        public void close() { delegate.close(); }
    }
    @Test void realInitialSuccessRestartDiscoveryAndSecondInitialGate() throws Exception {
        establish(); byte[] vault = Files.readAllBytes(sync.resolve("vault")), key = Files.readAllBytes(local.resolve("device-provenance-v1.bin"));
        ObjectId id; KnownDeviceNode expected;
        var faults = new ObjectPublicationFaults(LinuxDurability.open());
        try (var memory = LinuxSecurityMemoryStorage.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var publisher = faults.open(sync)) {
            var session = SecurityMemorySession.open(memory); var counted = new CountedKey(keys.openExisting());
            try (var identity = DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND, counted,
                    counted.vaultBinding(), counted.publicKeyX963())) {
                var discovery = DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session);
                assertEquals(DiscoveryState.READY, discovery.discoveryState());
                assertEquals(0, session.knowledge().size()); assertFalse(Files.exists(sync.resolve("objects-v1")));
                var result = publish(session, identity, discovery.discoveryState(), publisher);
                assertEquals(PUBLISHED_AND_REMEMBERED, result.status()); id = result.objectId();
                expected = authenticate(sync, id, ROOT, identity.publicKeyX963());
                assertEquals(expected, session.knowledge().record(id));
                int signs = counted.signs, calls = faults.events.size();
                assertEquals(DEVICE_FRONTIER_NOT_EMPTY, publish(session, identity, DiscoveryState.READY, publisher).status());
                assertEquals(signs, counted.signs); assertEquals(calls, faults.events.size());
                try (var files = Files.list(sync.resolve("objects-v1"))) { assertEquals(List.of(id.filename()), files.map(p -> p.getFileName().toString()).toList()); }
            }
        }
        assertArrayEquals(vault, Files.readAllBytes(sync.resolve("vault")));
        assertArrayEquals(key, Files.readAllBytes(local.resolve("device-provenance-v1.bin")));
        verifyRecovery(id, expected, true);
    }
    void verifyRecovery(ObjectId id, KnownDeviceNode expected, boolean initiallyPresent) throws Exception {
        try (var memory = LinuxSecurityMemoryStorage.open(local)) {
            var session = SecurityMemorySession.open(memory);
            assertEquals(initiallyPresent ? expected : null, session.knowledge().record(id));
            var discovery = DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session);
            assertEquals(DiscoveryState.READY, discovery.discoveryState());
            assertEquals(expected, session.knowledge().record(id));
            assertEquals(Set.of(id), discovery.topology().currentDeviceHeads(expected.deviceId()));
            var before = Files.readAllBytes(local.resolve("security-memory-v1.bin"));
            var again = DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session);
            assertEquals(DiscoveryState.READY, again.discoveryState());
            assertArrayEquals(before, Files.readAllBytes(local.resolve("security-memory-v1.bin")));
            assertEquals(expected, SecurityMemorySession.open(memory).knowledge().record(id));
        }
    }
    @Test void blockedReadinessLeavesNamespaceAbsentAndNeverSigns() throws Exception {
        establish();
        try (var memory = LinuxSecurityMemoryStorage.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var publisher = NioV1ObjectPublicationStore.open(sync, LinuxDurability.open())) {
            var session = SecurityMemorySession.open(memory); var counted = new CountedKey(keys.openExisting());
            try (var identity = DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND, counted,
                    counted.vaultBinding(), counted.publicKeyX963())) {
                assertEquals(AUTHORSHIP_NOT_READY, publish(session, identity, DiscoveryState.PROCESSING_INCOMPLETE, publisher).status());
                assertEquals(0, counted.signs); assertFalse(Files.exists(sync.resolve("objects-v1")));
            }
        }
    }
    @ParameterizedTest @ValueSource(strings = {"stage-sync", "root-sync", "post-link-sync", "directory-sync", "graph"})
    void realFailuresNeverReportOperationSuccessAndOrphansRecover(String failure) throws Exception {
        establish(); var faults = new ObjectPublicationFaults(LinuxDurability.open()); var memoryFaults = new StorageFaults();
        if (!failure.equals("graph")) faults.fail = failure;
        try (var memory = memoryFaults.open(local); var keys = LinuxDeviceProvenanceKeyStore.open(local);
             var publisher = faults.open(sync)) {
            var session = SecurityMemorySession.open(memory);
            try (var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys)) {
                var discovery = DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session);
                if (failure.equals("graph")) faults.action = point -> { if (point.equals("directory-sync")) memoryFaults.failWrite = true; };
                var result = publish(session, identity, discovery.discoveryState(), publisher);
                assertEquals(failure.equals("graph") ? KNOWLEDGE_PERSISTENCE_FAILED : PUBLICATION_INCOMPLETE, result.status());
                assertEquals(0, session.knowledge().size());
            }
        }
        if (Set.of("post-link-sync", "directory-sync", "graph").contains(failure)) {
            ObjectId id;
            try (var files = Files.list(sync.resolve("objects-v1"))) { id = ObjectId.fromFilename(files.findFirst().orElseThrow().getFileName().toString()); }
            try (var keys = LinuxDeviceProvenanceKeyStore.open(local); var key = keys.openExisting()) {
                verifyRecovery(id, authenticate(sync, id, ROOT, key.publicKeyX963()), false);
            }
        } else try (var files = Files.list(sync.resolve("objects-v1"))) { assertEquals(0, files.count()); }
    }
    @ParameterizedTest @ValueSource(strings = {"exact", "collision", "existing-file-sync", "existing-directory-sync", "changed", "missing"})
    void fixedSignedFixtureExactRecoveryAndCollisionWithRealGraph(String mode) throws Exception {
        var fixture = NioTestFixtures.fixture("v1.crypto.device-root.001");
        sync = Files.createDirectory(dir.resolve("sync")); local = Files.createDirectory(dir.resolve("local"));
        create(sync, local, fixture.root());
        Path target = Files.createDirectory(sync.resolve("objects-v1")).resolve(fixture.id().filename());
        Files.write(target, fixture.bytes()); // Existence alone is not the writer acknowledgement.
        var faults = new ObjectPublicationFaults(LinuxDurability.open()); faults.fail = mode;
        if (mode.equals("collision")) Files.write(sync.resolve("objects-v1").resolve(fixture.id().filename()), new byte[1024]);
        var memoryFaults = new StorageFaults();
        try (var fresh = faults.open(sync); var memory = memoryFaults.open(local)) {
            var session = SecurityMemorySession.open(memory); assertEquals(0, session.knowledge().size());
            boolean[] acknowledged = {false};
            faults.action = point -> {
                assertEquals(0, memoryFaults.writes, "graph must wait for EXACT acknowledgement");
                if (point.equals("existing-reread")) {
                    if (mode.equals("changed")) Files.write(target, new byte[1024]);
                    if (mode.equals("missing")) Files.delete(target);
                }
            };
            var ordered = new V1ObjectPublicationStore() {
                public PublicationResult publishDurably(ObjectId id, byte[] bytes) throws IOException {
                    var result = fresh.publishDurably(id, bytes);
                    assertEquals(PublicationResult.ALREADY_PRESENT_EXACT, result);
                    assertEquals(List.of("existing-read", "existing-file-sync", "existing-directory-sync", "existing-reread"),
                            faults.events.stream().filter(e -> e.startsWith("existing-")).toList());
                    assertEquals(0, memoryFaults.writes); assertEquals(0, session.knowledge().size());
                    acknowledged[0] = true;
                    return result;
                }
                public void close() {}
            };
            var read = EnvelopeReader.open(fixture.id().filename(), fixture.bytes(), fixture.root());
            var assertion = AssertionValidator.validate(read);
            assertEquals(ProvenanceStatus.VERIFIED, ProvenanceEvaluator.evaluate(assertion.object(), fixture.root(), VerificationKeyMaterial.available(List.of())));
            var observation = AuthenticatedObservation.supported(assertion.object());
            // Fixed corpus signature is a deterministic test signer only; the clean/halt paths use real custody.
            var signer = new DeviceProvenanceKey() {
                public byte[] vaultBinding() { return session.establishment().binding().bytes(); }
                public byte[] publicKeyX963() { return read.plaintext().device().publicKey(); }
                public byte[] signSha256Ecdsa(byte[] message) { return read.plaintext().signature(); }
                public void close() {}
            };
            try (var identity = DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND, signer,
                    signer.vaultBinding(), signer.publicKeyX963())) {
                var result = InitialDeviceAdvertisement.publish(fixture.root(),
                        () -> new InitialDeviceAdvertisement.Context(session, DiscoveryState.READY, 0), identity,
                        "Fixture device", new byte[8], ordered);
                assertEquals(mode.equals("exact") ? PUBLISHED_AND_REMEMBERED : PUBLICATION_INCOMPLETE, result.status());
                assertEquals(mode.equals("exact"), acknowledged[0]);
                assertEquals(mode.equals("exact") ? 1 : 0, memoryFaults.writes);
                if (mode.equals("exact")) {
                    assertEquals(fixture.id(), result.objectId());
                    assertEquals(V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT, result.publication());
                    assertEquals(observation.record(), SecurityMemorySession.open(memory).knowledge().record(fixture.id()));
                } else assertEquals(0, SecurityMemorySession.open(memory).knowledge().size());
                if (mode.equals("missing")) assertFalse(Files.exists(target));
                else assertArrayEquals(Set.of("collision", "changed").contains(mode) ? new byte[1024] : fixture.bytes(),
                        Files.readAllBytes(target));
            }
        }
    }
    Process child(String mode) throws Exception {
        var paths = new ArrayList<String>();
        for (Class<?> type : List.of(ObjectPublicationFaults.class, LinuxDurability.class, ObjectPublicationCrashProcess.class, NioV1ObjectPublicationStore.class, ObjectId.class))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        return new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny", "-cp", String.join(File.pathSeparator, paths),
                ObjectPublicationCrashProcess.class.getName(), mode, sync.toString(), local.toString()).redirectErrorStream(true).start();
    }
    @ParameterizedTest @ValueSource(strings = {"open", "staged", "linked", "returned", "full", "pregraph"})
    void sixProcessHaltBoundaries(String mode) throws Exception {
        establish(); byte[] vault = Files.readAllBytes(sync.resolve("vault")), keyBytes = Files.readAllBytes(local.resolve("device-provenance-v1.bin"));
        var process = child(mode); String output;
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS));
            output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
            assertEquals(0, process.exitValue(), output);
        } finally { process.destroyForcibly(); }
        assertArrayEquals(vault, Files.readAllBytes(sync.resolve("vault")));
        assertArrayEquals(keyBytes, Files.readAllBytes(local.resolve("device-provenance-v1.bin")));
        if (mode.equals("open")) { assertFalse(Files.exists(sync.resolve("objects-v1"))); return; }
        if (mode.equals("staged")) {
            try (var files = Files.list(sync.resolve("objects-v1"))) { assertTrue(files.allMatch(p -> p.getFileName().toString().startsWith(".totipo-object-"))); }
            try (var snapshot = new NioDiscoverySource(sync).snapshot()) { assertTrue(snapshot.candidates().isEmpty()); } return;
        }
        ObjectId id = ObjectId.fromFilename(output);
        try (var keys = LinuxDeviceProvenanceKeyStore.open(local); var key = keys.openExisting()) {
            var expected = authenticate(sync, id, ROOT, key.publicKeyX963());
            verifyRecovery(id, expected, mode.equals("full"));
        }
    }
}
