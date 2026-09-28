package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialDeviceAdvertisement.Status.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class InitialDeviceAdvertisementTest {
    static final class Harness implements AutoCloseable {
        final byte[] root = new byte[32];
        final MemoryJournalStorage memory = DeviceIdentityLifecycleTest.established(DeviceIdentityLifecycleTest.binding(root));
        SecurityMemorySession session = SecurityMemorySession.open(memory);
        final FakeDeviceKeyStore keys = new FakeDeviceKeyStore();
        final DeviceIdentityResult identity = DeviceIdentityLifecycle.createNew(session.head(), keys);
        final FakeV1ObjectPublicationStore store = new FakeV1ObjectPublicationStore();
        DiscoveryState discovery = DiscoveryState.READY;
        long revision;
        Harness() throws Exception { keys.signs = 0; }
        InitialDeviceAdvertisement.Context context() { return new InitialDeviceAdvertisement.Context(session, discovery, revision); }
        InitialDeviceAdvertisement.Result run() { return run(() -> {}); }
        InitialDeviceAdvertisement.Result run(Runnable hook) {
            return InitialDeviceAdvertisement.publish(root, this::context, identity, "local", new byte[8], store, hook);
        }
        void noWrites(int appends) { assertEquals(0, keys.signs); assertEquals(0, store.calls); assertEquals(appends, memory.appends); }
        @Override public void close() { identity.close(); keys.close(); store.close(); }
    }
    static ObjectId id(int value) { byte[] bytes = new byte[32]; bytes[0] = (byte) value; return new ObjectId(bytes); }
    static KnownDeviceNode node(DeviceIdentityResult identity, boolean opaque, int id) {
        return new KnownDeviceNode(id(id), opaque ? 2 : 1,
                opaque ? SemanticStatus.OPAQUE_ROUTABLE : SemanticStatus.SUPPORTED_VALID,
                new SecurityBytes(identity.deviceId(), 32), List.of(), BigInteger.ZERO,
                opaque ? null : new SecurityBytes(identity.publicKeyX963(), 65));
    }
    @Test void publicationBeforeGraphAndSuccessAfterBothWithNoCustodyMutation() throws Exception {
        try (var h = new Harness()) {
            byte[] publicKey = h.identity.publicKeyX963(); byte[] binding = h.keys.binding.clone();
            h.store.afterSnapshot = () -> assertEquals(0, h.session.knowledge().size());
            h.memory.beforeAppend = () -> assertEquals(1, h.store.snapshot().size());
            var result = h.run();
            assertEquals(PUBLISHED_AND_REMEMBERED, result.status());
            assertEquals(V1ObjectPublicationStore.PublicationResult.PUBLISHED_NEW, result.publication());
            assertEquals(1, h.keys.signs); assertEquals(1, h.store.calls);
            var node = (KnownDeviceNode) h.session.knowledge().record(result.objectId());
            assertEquals(1, node.objectVersion()); assertEquals(SemanticStatus.SUPPORTED_VALID, node.semanticStatus());
            assertEquals(result.deviceId(), node.deviceId()); assertTrue(node.parents().isEmpty());
            assertEquals(BigInteger.ZERO, node.authorTime());
            assertArrayEquals(h.identity.publicKeyX963(), node.publicKeyX963().bytes());
            assertEquals(node, SecurityMemorySession.open(h.memory).knowledge().record(result.objectId()));
            assertArrayEquals(publicKey, h.identity.publicKeyX963()); assertArrayEquals(binding, h.keys.binding); assertEquals(1, h.keys.creates);
            assertEquals(DEVICE_FRONTIER_NOT_EMPTY, h.run().status());
            assertEquals(1, h.keys.signs); assertEquals(1, h.store.calls);
        }
    }
    @ParameterizedTest @ValueSource(strings = {"incomplete", "unknown", "blocked", "unscoped"})
    void readinessBlocksBeforeSigning(String kind) throws Exception {
        try (var h = new Harness()) {
            switch (kind) {
                case "incomplete" -> h.discovery = DiscoveryState.PROCESSING_INCOMPLETE;
                case "unknown" -> h.session.markUnknown();
                case "blocked" -> { h.memory.failAppend = true; h.session.commitRecord(node(h.identity, false, 4)); }
                case "unscoped" -> h.session.commitRecord(new OpaqueUnscopedRecord(id(7), new SecurityBytes(new byte[1024], 1024)));
                default -> fail();
            }
            int before = h.memory.appends;
            assertEquals(AUTHORSHIP_NOT_READY, h.run().status()); h.noWrites(before);
        }
    }
    @ParameterizedTest @ValueSource(strings = {"unestablished", "pending", "missing", "corrupt", "tail"})
    void establishmentAndMemoryGates(String kind) throws Exception {
        try (var h = new Harness()) {
            var memory = new MemoryJournalStorage();
            if (kind.equals("unestablished")) { SecurityMemorySession.initializeNew(memory); }
            if (kind.equals("pending")) { SecurityMemorySession.initializeNew(memory).persistPending(DeviceIdentityLifecycleTest.binding(h.root)); }
            if (kind.equals("corrupt") || kind.equals("tail")) {
                memory.bytes = h.memory.bytes.clone();
                if (kind.equals("corrupt")) { memory.bytes[memory.bytes.length - 1] ^= 1; }
                else { memory.bytes = Arrays.copyOf(memory.bytes, memory.bytes.length + 1); }
            }
            h.session = SecurityMemorySession.open(memory);
            byte[] before = memory.bytes == null ? null : memory.bytes.clone();
            assertEquals(LOCAL_STATE_NOT_ESTABLISHED, h.run().status());
            assertEquals(0, h.keys.signs); assertEquals(0, h.store.calls); assertArrayEquals(before, memory.bytes);
        }
    }
    @Test void threeWayBindingAndUnavailableIdentity() throws Exception {
        try (var h = new Harness()) {
            int before = h.memory.appends;
            h.root[0] = 1;
            assertEquals(DEVICE_IDENTITY_BINDING_MISMATCH, h.run().status()); h.root[0] = 0;
            var other = new FakeDeviceKeyStore(); other.seed(new byte[32]);
            try (var handle = other.openExisting();
                 var identity = DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND,
                    handle, new byte[32], handle.publicKeyX963())) {
                assertEquals(DEVICE_IDENTITY_BINDING_MISMATCH, InitialDeviceAdvertisement.publish(h.root, h::context,
                        identity, "", new byte[8], h.store).status());
                assertEquals(0, other.signs);
            }
            h.identity.close(); assertEquals(DEVICE_IDENTITY_UNAVAILABLE, h.run().status()); h.noWrites(before);
        }
    }
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void supportedAndOpaqueOwnHeadsBlock(boolean opaque) throws Exception {
        try (var h = new Harness()) {
            h.session.commitRecord(node(h.identity, opaque, 9)); int before = h.memory.appends;
            assertEquals(DEVICE_FRONTIER_NOT_EMPTY, h.run().status()); h.noWrites(before);
        }
    }
    @Test void otherDeviceAndTokenConflictsAndOpaqueTokenDoNotDefineOwnFrontier() throws Exception {
        try (var h = new Harness()) {
            var other = new SecurityBytes(new byte[32], 32);
            h.session.commitRecord(new KnownDeviceNode(id(1), 2, SemanticStatus.OPAQUE_ROUTABLE,
                    other, List.of(), BigInteger.ZERO, null));
            // Deliberately reuse the local DEVICE_ID as a TOKEN_ID: type is part of graph scope.
            var token = new SecurityBytes(h.identity.deviceId(), 32);
            for (int i = 2; i < 5; i++) {
                h.session.commitRecord(new KnownTokenNode(id(i), i == 4 ? 2 : 1,
                        i == 4 ? SemanticStatus.OPAQUE_ROUTABLE : SemanticStatus.SUPPORTED_VALID,
                        token, List.of(), other, BigInteger.ZERO));
            }
            assertEquals(PUBLISHED_AND_REMEMBERED, h.run().status()); assertEquals(5, h.session.knowledge().size());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"a", "\ud800"})
    void invalidNamesDoNotSign(String input) throws Exception {
        try (var h = new Harness()) {
            int before = h.memory.appends;
            assertEquals(INVALID_DISPLAY_NAME, InitialDeviceAdvertisement.publish(h.root, h::context, h.identity,
                    input.equals("a") ? input.repeat(257) : input, new byte[8], h.store).status()); h.noWrites(before);
        }
    }
    @ParameterizedTest @EnumSource(value = FakeDeviceKeyStore.SignFault.class, names = "NONE", mode = EnumSource.Mode.EXCLUDE)
    void signerFailuresNeverPublish(FakeDeviceKeyStore.SignFault fault) throws Exception {
        try (var h = new Harness()) {
            h.keys.signFault = fault; int before = h.memory.appends;
            assertEquals(SIGNING_FAILED, h.run().status());
            assertEquals(1, h.keys.signs); assertEquals(0, h.store.calls); assertEquals(before, h.memory.appends);
        }
    }
    @ParameterizedTest @EnumSource(value = FakeV1ObjectPublicationStore.Fault.class, names = "NONE", mode = EnumSource.Mode.EXCLUDE)
    void publicationFailuresNeverCommitOrRetry(FakeV1ObjectPublicationStore.Fault fault) throws Exception {
        try (var h = new Harness()) {
            h.store.fault = fault; byte[] before = h.memory.bytes.clone();
            assertEquals(PUBLICATION_INCOMPLETE, h.run().status());
            assertEquals(1, h.keys.signs); assertEquals(1, h.store.calls);
            assertArrayEquals(before, h.memory.bytes); assertEquals(0, h.session.knowledge().size());
            if (fault == FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL) { recover(h); }
        }
    }
    @Test void graphFailureLeavesOrphanAndRestartDiscoveryRecoversIt() throws Exception {
        try (var h = new Harness()) {
            h.memory.failAppend = true;
            assertEquals(KNOWLEDGE_PERSISTENCE_FAILED, h.run().status());
            assertTrue(h.session.knowledge().knowledgePersistenceBlocked());
            assertEquals(1, h.store.snapshot().size()); assertEquals(0, h.session.knowledge().size());
            assertEquals(AUTHORSHIP_NOT_READY, h.run().status()); assertEquals(1, h.keys.signs);
            h.memory.failAppend = false;
            recover(h);
        }
    }
    private static void recover(Harness h) throws Exception {
        var source = new DiscoveryFixtures(); h.store.snapshot().forEach(source::put);
        var fresh = SecurityMemorySession.open(h.memory);
        var result = DiscoveryCoordinator.discover(source, h.root, fresh);
        assertEquals(DiscoveryState.READY, result.discoveryState());
        var entry = h.store.snapshot().entrySet().iterator().next();
        var node = (KnownDeviceNode) fresh.knowledge().record(entry.getKey());
        assertEquals(new SecurityBytes(h.identity.deviceId(), 32), node.deviceId());
        assertArrayEquals(h.identity.publicKeyX963(), node.publicKeyX963().bytes());
        assertTrue(node.parents().isEmpty()); assertEquals(BigInteger.ZERO, node.authorTime());
        assertEquals(node, SecurityMemorySession.open(h.memory).knowledge().record(entry.getKey()));
        assertArrayEquals(entry.getValue(), h.store.get(entry.getKey()));
    }
    @ParameterizedTest @ValueSource(strings = {"head", "opaqueHead", "incomplete", "revision", "unknown", "blocked", "identityClosed", "session"})
    void freshnessChangesAbortWithoutSecondSignature(String change) throws Exception {
        try (var h = new Harness()) {
            var result = h.run(() -> {
                switch (change) {
                    case "head", "opaqueHead" -> h.session.commitRecord(node(h.identity, change.equals("opaqueHead"), 3));
                    case "incomplete" -> h.discovery = DiscoveryState.PROCESSING_INCOMPLETE;
                    case "revision" -> h.revision++; // includes READY -> incomplete -> READY between snapshots
                    case "unknown" -> h.session.markUnknown();
                    case "blocked" -> { h.memory.failAppend = true; h.session.commitRecord(node(h.identity, false, 3)); }
                    case "identityClosed" -> h.identity.close();
                    case "session" -> { try { h.session = SecurityMemorySession.open(h.memory); } catch (Exception e) { throw new AssertionError(e); } }
                    default -> fail();
                }
            });
            assertEquals(OPERATION_STALE, result.status()); assertEquals(0, h.store.calls); assertEquals(1, h.keys.signs);
            assertEquals(change.equals("head") || change.equals("opaqueHead") ? 1 : 0, h.session.knowledge().size());
        }
    }
    @Test void exactExistingCandidateMayCompleteGraphAfterFailedAppend() throws Exception {
        var root = DeviceWriterTest.root();
        var memory = DeviceIdentityLifecycleTest.established(DeviceIdentityLifecycleTest.binding(root));
        var session = SecurityMemorySession.open(memory);
        var key = new DeviceWriterTest.CapturingKey();
        key.fixedSignature = DeviceWriterTest.fixture().data().field("crypto").field("signature_der_hex").hex();
        var store = new FakeV1ObjectPublicationStore();
        memory.failAppend = true;
        var first = InitialDeviceAdvertisement.publish(root, () -> new InitialDeviceAdvertisement.Context(session, DiscoveryState.READY, 0),
                key.identity(), "Fixture device", new byte[8], store);
        assertEquals(KNOWLEDGE_PERSISTENCE_FAILED, first.status());
        memory.failAppend = false;
        var restarted = SecurityMemorySession.open(memory);
        var retry = InitialDeviceAdvertisement.publish(root, () -> new InitialDeviceAdvertisement.Context(restarted, DiscoveryState.READY, 0),
                key.identity(), "Fixture device", new byte[8], store);
        assertEquals(PUBLISHED_AND_REMEMBERED, retry.status());
        assertEquals(V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT, retry.publication());
        assertEquals(1, store.snapshot().size()); assertEquals(1, restarted.knowledge().size());
        var read = EnvelopeReader.open(retry.objectId().filename(), store.get(retry.objectId()), root);
        var observation = AuthenticatedObservation.supported(AssertionValidator.validate(read).object());
        int appends = memory.appends;
        assertEquals(DurableKnowledgeState.Outcome.UNCHANGED, restarted.commit(observation).outcome());
        assertEquals(appends, memory.appends);
        var old = (KnownDeviceNode) observation.record();
        assertEquals(DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN, restarted.commitRecord(new KnownDeviceNode(
                old.objectId(), 1, old.semanticStatus(), old.deviceId(), old.parents(), BigInteger.ONE, old.publicKeyX963())).outcome());
    }
}
