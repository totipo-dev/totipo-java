package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;
import java.util.ArrayList;
import java.util.List;
import dev.totipo.conformance.VectorCaseLoader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class InitialTokenPublicationTest {
    static TokenValue value() { return new TokenValue(1, "", "", new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[]{42}, 1))); }
    static InitialTokenPublication.Result publish(InitialDeviceAdvertisementTest.Harness h,
            List<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable hook) {
        return InitialTokenPublication.publish(h.root, h::context, h.identity, value(), new byte[8], h.store,
                evidence, bytes -> java.util.Arrays.fill(bytes, (byte) 17), hook);
    }
    static TokenPublicationSuccessGate.VerifiedDeviceAdvertisement evidence(InitialDeviceAdvertisementTest.Harness h, ObjectId id) {
        return TokenPublicationSuccessGate.VerifiedDeviceAdvertisement.read(id, h.store.get(id), h.root, VerificationKeyMaterial.keys());
    }
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void bothOrdersAndRestart(boolean deviceFirst) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            var ads = new ArrayList<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement>();
            if (deviceFirst) { ads.add(evidence(h, h.run().objectId())); }
            int before = h.session.knowledge().size();
            h.store.afterSnapshot = () -> assertEquals(before, h.session.knowledge().size());
            var result = publish(h, ads, () -> {});
            assertEquals(deviceFirst ? PUBLISHED_AND_REMEMBERED_SUCCESS_READY : PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED, result.status());
            assertEquals(new SecurityBytes(java.util.HexFormat.of().parseHex("11".repeat(32)), 32), result.receipt().tokenId());
            h.store.afterSnapshot = () -> {};
            h.session = SecurityMemorySession.open(h.memory);
            if (!deviceFirst) {
                assertFalse(TokenPublicationSuccessGate.allows(h.session, result.receipt(), h.identity.publicKeyX963(), ads));
                ads.add(evidence(h, h.run().objectId()));
            }
            assertTrue(TokenPublicationSuccessGate.allows(h.session, result.receipt(), h.identity.publicKeyX963(), ads));
            assertEquals(2, h.keys.signs); assertEquals(2, h.store.calls);
            assertEquals(TOKEN_ID_COLLISION, publish(h, ads, () -> {}).status());
            assertEquals(2, h.keys.signs);
        }
    }
    @ParameterizedTest @EnumSource(value = FakeDeviceKeyStore.SignFault.class, names = "NONE", mode = EnumSource.Mode.EXCLUDE)
    void badSignerNeverPublishes(FakeDeviceKeyStore.SignFault fault) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            h.keys.signFault = fault;
            assertEquals(SIGNING_FAILED, publish(h, List.of(), () -> {}).status());
            assertEquals(1, h.keys.signs); assertEquals(0, h.store.calls); assertEquals(0, h.session.knowledge().size());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"incomplete", "unknown", "blocked", "unscoped", "closed", "root"})
    void readinessBeforeEntropy(String change) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            switch (change) {
                case "incomplete" -> h.discovery = DiscoveryState.PROCESSING_INCOMPLETE;
                case "unknown" -> h.session.markUnknown();
                case "blocked" -> { h.memory.failAppend = true; h.session.commitRecord(InitialDeviceAdvertisementTest.node(h.identity, false, 4)); }
                case "unscoped" -> h.session.commitRecord(new OpaqueUnscopedRecord(InitialDeviceAdvertisementTest.id(7), new SecurityBytes(new byte[1024], 1024)));
                case "closed" -> h.identity.close();
                case "root" -> h.root[0] = 1;
                default -> fail();
            }
            var result = InitialTokenPublication.publish(h.root, h::context, h.identity, value(), new byte[8], h.store,
                    List.of(), bytes -> fail("Entropy before readiness"), () -> {});
            assertNull(result.receipt()); assertEquals(0, h.keys.signs); assertEquals(0, h.store.calls);
        }
    }
    @Test void freshnessAndGraphFailure() throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            assertEquals(OPERATION_STALE, publish(h, List.of(), () -> h.revision++).status());
            assertEquals(0, h.store.calls);
            h.memory.failAppend = true;
            assertEquals(KNOWLEDGE_PERSISTENCE_FAILED, publish(h, List.of(), () -> {}).status());
            assertEquals(1, h.store.snapshot().size()); assertTrue(h.session.knowledge().knowledgePersistenceBlocked());
            h.memory.failAppend = false; h.session = SecurityMemorySession.open(h.memory);
            var source = new DiscoveryFixtures(); h.store.snapshot().forEach(source::put);
            assertEquals(DiscoveryState.READY, DiscoveryCoordinator.discover(source, h.root, h.session).discoveryState());
            assertEquals(1, h.session.knowledge().size());
        }
    }
    @ParameterizedTest @EnumSource(value = FakeV1ObjectPublicationStore.Fault.class,
            names = {"NONE", "EXISTING_ACKNOWLEDGEMENT"}, mode = EnumSource.Mode.EXCLUDE)
    void publicationFailureNeverCommits(FakeV1ObjectPublicationStore.Fault fault) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            h.store.fault = fault;
            assertEquals(PUBLICATION_INCOMPLETE, publish(h, List.of(), () -> {}).status());
            assertEquals(0, h.session.knowledge().size()); assertEquals(1, h.keys.signs);
        }
    }

    /** Execute the symbolic contract with real signing, reading, provenance and journal boundaries. */
    static void vector(VectorCaseLoader.Case c) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            var contract = c.data().field("publication");
            var ads = new ArrayList<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement>();
            InitialTokenPublication.Receipt receipt = null;
            int workflow = 0;
            for (var event : contract.field("events").array()) {
                switch (event.field("action").string()) {
                    case "restart-workflow" -> {
                        h.session = SecurityMemorySession.open(h.memory);
                        ads.clear(); receipt = null; workflow++;
                    }
                    case "publish-token" -> {
                        h.store.fault = event.field("durable").bool() ? FakeV1ObjectPublicationStore.Fault.NONE
                                : FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL;
                        final int draw = workflow + 1;
                        var result = InitialTokenPublication.publish(h.root, h::context, h.identity, value(), new byte[8],
                                h.store, ads, bytes -> java.util.Arrays.fill(bytes, (byte) draw), () -> {});
                        receipt = result.receipt();
                        assertEquals(event.field("durable").bool(), receipt != null);
                        h.store.fault = FakeV1ObjectPublicationStore.Fault.NONE;
                    }
                    case "advertise" -> {
                        // Unique AUTHOR_TIME prevents an earlier unverified durable node from
                        // accidentally standing in for a later explicitly nondurable candidate.
                        byte[] time = java.nio.ByteBuffer.allocate(8).putLong(h.keys.signs + 1).array();
                        byte[] semantic = DeviceWriter.signed(h.root, h.identity, "local", time, List.of());
                        if (!event.field("device_id").string().equals(contract.field("device_id").string())) {
                            semantic = TlvTestBytes.replace(semantic, 0x0200, new byte[32]);
                        }
                        if (!event.field("public_key").string().equals(contract.field("public_key").string())) {
                            semantic = TlvTestBytes.replace(semantic, 0x0201, DeviceWriterTest.KEY);
                        }
                        if (!event.field("assertion_valid").bool()) {
                            semantic = TlvTestBytes.replace(semantic, 0x0200, new byte[32]);
                        }
                        if (!event.field("verified").bool()) { semantic[semantic.length - 1] ^= 1; }
                        var object = V1EnvelopeWriter.seal(h.root, semantic);
                        var opened = EnvelopeReader.open(object.id().filename(), object.bytes(), h.root);
                        var assertion = AssertionValidator.validate(opened);
                        if (event.field("durable").bool()) {
                            h.store.publishDurably(object.id(), object.bytes());
                            if (assertion.object() != null) { h.session.commit(AuthenticatedObservation.supported(assertion.object())); }
                        }
                        var ad = TokenPublicationSuccessGate.VerifiedDeviceAdvertisement.read(object.id(), object.bytes(), h.root,
                                VerificationKeyMaterial.keys());
                        if (ad != null) { ads.add(ad); }
                    }
                    case "report-success" -> assertEquals(event.field("success").bool(),
                            TokenPublicationSuccessGate.allows(h.session, receipt, h.identity.publicKeyX963(), ads));
                    default -> fail("Unknown publication action");
                }
            }
            assertEquals("PASS", c.expected());
        }
    }
    @Test void verifiedCurrentBytesNeedDurableRecordAndUnavailableVerificationCannotSubstitute() throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness(); var other = new InitialDeviceAdvertisementTest.Harness()) {
            var receipt = publish(h, List.of(), () -> {}).receipt();
            byte[] semantic = DeviceWriter.signed(h.root, h.identity, "", new byte[8], List.of());
            var object = V1EnvelopeWriter.seal(h.root, semantic);
            var evidence = TokenPublicationSuccessGate.VerifiedDeviceAdvertisement.read(object.id(), object.bytes(), h.root, VerificationKeyMaterial.keys());
            assertNotNull(evidence);
            assertNull(TokenPublicationSuccessGate.VerifiedDeviceAdvertisement.read(object.id(), object.bytes(), h.root, VerificationKeyMaterial.temporarilyUnavailable()));
            assertFalse(TokenPublicationSuccessGate.allows(h.session, receipt, h.identity.publicKeyX963(), List.of(evidence)));
            var wrong = DeviceWriter.signed(h.root, other.identity, "", new byte[8], List.of());
            var wrongObject = V1EnvelopeWriter.seal(h.root, wrong);
            h.store.publishDurably(wrongObject.id(), wrongObject.bytes());
            h.session.commit(AuthenticatedObservation.supported(AssertionValidator.validate(EnvelopeReader.open(wrongObject.id().filename(), wrongObject.bytes(), h.root)).object()));
            var wrongEvidence = TokenPublicationSuccessGate.VerifiedDeviceAdvertisement.read(wrongObject.id(), wrongObject.bytes(), h.root, VerificationKeyMaterial.keys());
            assertFalse(TokenPublicationSuccessGate.allows(h.session, receipt, h.identity.publicKeyX963(), List.of(wrongEvidence)));
            h.store.publishDurably(object.id(), object.bytes());
            h.session.commit(AuthenticatedObservation.supported(AssertionValidator.validate(EnvelopeReader.open(object.id().filename(), object.bytes(), h.root)).object()));
            assertTrue(TokenPublicationSuccessGate.allows(h.session, receipt, h.identity.publicKeyX963(), List.of(evidence)));
            assertFalse(TokenPublicationSuccessGate.allows(h.session, receipt, other.identity.publicKeyX963(), List.of(evidence)));
        }
    }
    @ParameterizedTest @ValueSource(strings = {"session", "revision", "discovery", "closed", "history", "unknown", "blocked"})
    void freshnessRecheckNeverRepublishesOrResigns(String change) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            var result = publish(h, List.of(), () -> {
                switch (change) {
                    case "session" -> { try { h.session = SecurityMemorySession.open(h.memory); } catch (Exception e) { throw new AssertionError(e); } }
                    case "revision" -> h.revision++;
                    case "discovery" -> h.discovery = DiscoveryState.PROCESSING_INCOMPLETE;
                    case "closed" -> h.identity.close();
                    case "unknown" -> h.session.markUnknown();
                    case "blocked" -> { h.memory.failAppend = true; h.session.commitRecord(InitialDeviceAdvertisementTest.node(h.identity, false, 3)); }
                    case "history" -> h.session.commitRecord(new KnownTokenNode(InitialDeviceAdvertisementTest.id(4), 2,
                            SemanticStatus.OPAQUE_ROUTABLE, new SecurityBytes(java.util.HexFormat.of().parseHex("11".repeat(32)), 32),
                            List.of(), new SecurityBytes(h.identity.deviceId(), 32), java.math.BigInteger.ZERO));
                    default -> fail();
                }
            });
            assertEquals(OPERATION_STALE, result.status()); assertEquals(1, h.keys.signs); assertEquals(0, h.store.calls);
        }
    }
    @Test void oneExactEntropyDrawAndTombstoneRootAllowed() throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            int[] draws = {0};
            var input = value(); var tombstone = new TokenValue(2, input.issuer(), input.account(), input.credential());
            var result = InitialTokenPublication.publish(h.root, h::context, h.identity, tombstone, new byte[8], h.store, List.of(),
                    bytes -> { assertEquals(32, bytes.length); draws[0]++; for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) i; }, () -> {});
            assertEquals(PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED, result.status()); assertEquals(1, draws[0]);
            for (int i = 0; i < 32; i++) assertEquals((byte) i, result.receipt().tokenId().bytes()[i]);
            var parsed = EnvelopeReader.open(result.receipt().objectId().filename(), h.store.get(result.receipt().objectId()), h.root).plaintext();
            assertEquals(tombstone, TokenValue.from(parsed.token())); assertTrue(parsed.routing().parents().isEmpty());
        }
    }
    @ParameterizedTest @ValueSource(strings = {"unestablished", "pending", "missing", "corrupt", "tail"})
    void establishmentBeforeEntropy(String state) throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            var memory = new MemoryJournalStorage();
            if (state.equals("unestablished")) SecurityMemorySession.initializeNew(memory);
            if (state.equals("pending")) SecurityMemorySession.initializeNew(memory).persistPending(DeviceIdentityLifecycleTest.binding(h.root));
            if (state.equals("corrupt") || state.equals("tail")) {
                memory.bytes = h.memory.bytes.clone();
                if (state.equals("corrupt")) memory.bytes[memory.bytes.length - 1] ^= 1;
                else memory.bytes = java.util.Arrays.copyOf(memory.bytes, memory.bytes.length + 1);
            }
            h.session = SecurityMemorySession.open(memory);
            assertEquals(LOCAL_STATE_NOT_ESTABLISHED, InitialTokenPublication.publish(h.root, h::context, h.identity,
                    value(), new byte[8], h.store, List.of(), bytes -> fail("Entropy before establishment"), () -> {}).status());
            assertEquals(0, h.keys.signs); assertEquals(0, h.store.calls);
        }
    }
    @Test void canonicalMathematicallyInvalidSignerNeverPublishes() throws Exception {
        try (var h = new InitialDeviceAdvertisementTest.Harness()) {
            byte[] invalid = DeviceWriterTest.hex("3006020100020100");
            assertTrue(EcdsaDerSignature.isCanonical(invalid));
            var signer = new DeviceProvenanceKey() {
                public byte[] vaultBinding() { return h.identity.vaultBinding(); }
                public byte[] publicKeyX963() { return h.identity.publicKeyX963(); }
                public byte[] signSha256Ecdsa(byte[] input) { return invalid.clone(); }
                public void close() {}
            };
            try (var identity = DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND, signer,
                    signer.vaultBinding(), signer.publicKeyX963())) {
                assertEquals(SIGNING_FAILED, InitialTokenPublication.publish(h.root, h::context, identity, value(), new byte[8],
                        h.store, List.of(), bytes -> {}, () -> {}).status());
                assertEquals(0, h.store.calls); assertEquals(0, h.session.knowledge().size());
            }
        }
    }
}
