package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DurableKnowledgeState.PersistenceResult.*;
import static dev.totipo.format.DurableKnowledgeState.Outcome.INSERTED;
import static dev.totipo.format.DurableKnowledgeState.Outcome.UNCHANGED;
import static dev.totipo.format.DurableKnowledgeState.Outcome.RECLASSIFICATION_REQUIRED;
import static dev.totipo.format.DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED;
import static dev.totipo.format.LocalContinuityStatus.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class DurableKnowledgeTest {
    static final List<String> FIXTURES = List.of("v1.crypto.token-child.001", "v1.crypto.device-root.001",
            "v1.crypto.future-token-opaque.001", "v1.crypto.future-device-opaque.001",
            "v1.routing.unknown-type-unscoped.001");

    static Case fixture(String id) throws Exception {
        var cases = new ArrayList<>(VectorCaseLoader.cryptoCases());
        cases.addAll(VectorCaseLoader.routingCases());
        return cases.stream().filter(c -> c.id().equals(id)).findFirst().orElseThrow();
    }

    static EnvelopeReader.Result open(Case c) {
        var crypto = c.data().field("crypto");
        return EnvelopeReader.open(crypto.field("object_id").string(), crypto.field("object_hex").hex(),
                c.data().field("root_hex").hex());
    }

    static AuthenticatedObservation observe(EnvelopeReader.Result result) {
        if (result.status() == EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE) {
            var assertion = AssertionValidator.validate(result);
            assertEquals(AssertionValidator.Status.ASSERTION_VALID, assertion.status());
            return AuthenticatedObservation.supported(assertion.object());
        }
        return AuthenticatedObservation.opaque(result).orElseThrow();
    }

    static DurableKnowledgeState learn(DurableKnowledgeState state, AuthenticatedObservation observation) {
        return state.afterPersistence(observation, COMMITTED).state();
    }

    @TestFactory
    List<DynamicTest> fiveProjectionsAndIdempotentReappearance() {
        return FIXTURES.stream().map(id -> DynamicTest.dynamicTest(id, () -> {
            var c = fixture(id);
            var opened = open(c);
            var observation = observe(opened);
            var record = observation.record();
            assertEquals(ObjectId.fromFilename(c.data().field("crypto").field("object_id").string()), record.objectId());
            if (record instanceof OpaqueUnscopedRecord unscoped) {
                assertArrayEquals(c.data().field("crypto").field("object_hex").hex(), unscoped.exactObjectBytes().bytes());
                assertEquals(1024, unscoped.exactObjectBytes().size());
                assertNull(opened.plaintext());
            } else {
                var p = opened.routing().prefix();
                var status = opened.plaintext() == null ? SemanticStatus.OPAQUE_ROUTABLE : SemanticStatus.SUPPORTED_VALID;
                if (record instanceof KnownTokenNode token) {
                    assertEquals(p.version(), token.objectVersion());
                    assertEquals(status, token.semanticStatus());
                    assertArrayEquals(p.identity(), token.tokenId().bytes());
                    assertArrayEquals(p.authorDeviceId(), token.authorDeviceId().bytes());
                    assertEquals(p.authorTime(), token.authorTime());
                    assertEquals(p.parents().stream().map(ObjectId::new).toList(), token.parents());
                } else {
                    var device = (KnownDeviceNode) record;
                    assertEquals(p.version(), device.objectVersion());
                    assertEquals(status, device.semanticStatus());
                    assertArrayEquals(p.identity(), device.deviceId().bytes());
                    assertEquals(p.authorTime(), device.authorTime());
                    assertEquals(p.parents().stream().map(ObjectId::new).toList(), device.parents());
                    if (status == SemanticStatus.OPAQUE_ROUTABLE) { assertNull(device.publicKeyX963()); }
                    else { assertArrayEquals(opened.plaintext().device().publicKey(), device.publicKeyX963().bytes()); }
                }
            }
            var empty = DurableKnowledgeState.establishedEmpty();
            var first = empty.afterPersistence(observation, COMMITTED);
            assertEquals(INSERTED, first.outcome());
            assertEquals(0, empty.size());
            var repeated = first.state().afterPersistence(observe(open(c)), COMMITTED);
            assertEquals(UNCHANGED, repeated.outcome());
            assertSame(first.state(), repeated.state());
            assertEquals(1, repeated.state().size());
            assertEquals(LOCAL_CONTINUITY_KNOWN, repeated.state().continuity());
            assertEquals(record, observe(open(c)).record());
            assertEquals(record.hashCode(), observe(open(c)).record().hashCode());
        })).toList();
    }

    @Test
    void recordsHaveOnlyMinimumFieldsIncludingNoOpaqueBodyOrCredential() {
        assertEquals(List.of("objectId", "objectVersion", "semanticStatus", "tokenId", "parents", "authorDeviceId", "authorTime"),
                Arrays.stream(KnownTokenNode.class.getRecordComponents()).map(java.lang.reflect.RecordComponent::getName).toList());
        assertEquals(List.of("objectId", "objectVersion", "semanticStatus", "deviceId", "parents", "authorTime", "publicKeyX963"),
                Arrays.stream(KnownDeviceNode.class.getRecordComponents()).map(java.lang.reflect.RecordComponent::getName).toList());
        assertEquals(List.of("objectId", "exactObjectBytes"),
                Arrays.stream(OpaqueUnscopedRecord.class.getRecordComponents()).map(java.lang.reflect.RecordComponent::getName).toList());
    }

    @Test
    void rejectedAndUnresolvedProvenanceNeverGateEitherSupportedProjection() throws Exception {
        for (var c : List.of(ProvenanceTest.token(), ProvenanceTest.device())) {
            var valid = AssertionValidator.validate(open(c)).object();
            assertEquals(ProvenanceStatus.UNRESOLVED, ProvenanceEvaluator.evaluate(valid, ProvenanceTest.root(c),
                    VerificationKeyMaterial.temporarilyUnavailable()));
            var unresolved = AuthenticatedObservation.supported(valid);
            byte[] rejectedBytes = TlvTestBytes.replace(c.semanticBytes(), 0xff01, new byte[0]);
            var rejected = ProvenanceTest.valid(rejectedBytes, ProvenanceTest.root(c));
            assertEquals(ProvenanceStatus.REJECTED, ProvenanceTest.evaluate(rejected, ProvenanceTest.root(c)));
            var projection = AuthenticatedObservation.supported(rejected);
            assertEquals(1, learn(DurableKnowledgeState.establishedEmpty(), projection).size());
            if (projection.record() instanceof KnownDeviceNode d) {
                assertArrayEquals(ProvenanceTest.key(c), d.publicKeyX963().bytes());
                assertEquals(((KnownDeviceNode) unresolved.record()).publicKeyX963(), d.publicKeyX963());
            }
        }
        byte[] key = new byte[65]; key[0] = 4; // Off-curve is not an assertion failure.
        var c = ProvenanceTest.device();
        var bytes = TlvTestBytes.replace(TlvTestBytes.replace(c.semanticBytes(), 0x0201, key), 0x0200, P256.deviceId(key));
        var d = (KnownDeviceNode) observe(ProvenanceTest.authenticate(bytes, ProvenanceTest.root(c))).record();
        assertArrayEquals(key, d.publicKeyX963().bytes());
    }

    @Test
    void invalidAndUnauthenticatedResultsCannotProduceObservations() throws Exception {
        var c = ProvenanceTest.device();
        byte[] wrongIdentity = new byte[32];
        var invalid = ProvenanceTest.authenticate(TlvTestBytes.replace(c.semanticBytes(), 0x0200, wrongIdentity), ProvenanceTest.root(c));
        assertNull(AssertionValidator.validate(invalid).object());
        assertTrue(AuthenticatedObservation.opaque(invalid).isEmpty());
        var broken = ProvenanceTest.authenticate(new byte[0], ProvenanceTest.root(c));
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_INVALID_STRUCTURE, broken.status());
        assertTrue(AuthenticatedObservation.opaque(broken).isEmpty());
        var crypto = c.data().field("crypto");
        for (byte[] bytes : List.of(new byte[0], new byte[1024], new byte[1025])) {
            assertTrue(AuthenticatedObservation.opaque(EnvelopeReader.open(crypto.field("object_id").string(), bytes,
                    ProvenanceTest.root(c))).isEmpty());
        }
        assertTrue(AuthenticatedObservation.opaque(open(c)).isEmpty()); // Structure alone is insufficient.
        assertTrue(Arrays.stream(AuthenticatedObservation.class.getDeclaredConstructors())
                .allMatch(k -> java.lang.reflect.Modifier.isPrivate(k.getModifiers())));
        assertTrue(Arrays.stream(EnvelopeReader.Result.class.getDeclaredConstructors())
                .allMatch(k -> java.lang.reflect.Modifier.isPrivate(k.getModifiers())));
    }

    @Test
    void allByteSourcesAndAccessorsAreDefensivelyOwned() throws Exception {
        byte[] id = new byte[32], identity = new byte[32], author = new byte[32], parent = new byte[32], key = new byte[65];
        id[0] = 1; identity[0] = 2; author[0] = 3; parent[0] = 4; key[0] = 4;
        var parents = new ArrayList<>(List.of(new ObjectId(parent)));
        var token = new KnownTokenNode(new ObjectId(id), 1, SemanticStatus.SUPPORTED_VALID,
                new SecurityBytes(identity, 32), parents, new SecurityBytes(author, 32), BigInteger.ZERO);
        var device = new KnownDeviceNode(new ObjectId(id), 1, SemanticStatus.SUPPORTED_VALID,
                new SecurityBytes(identity, 32), parents, BigInteger.ZERO, new SecurityBytes(key, 65));
        var expectedToken = new KnownTokenNode(new ObjectId(id), 1, SemanticStatus.SUPPORTED_VALID,
                new SecurityBytes(identity, 32), parents, new SecurityBytes(author, 32), BigInteger.ZERO);
        var expectedDevice = new KnownDeviceNode(new ObjectId(id), 1, SemanticStatus.SUPPORTED_VALID,
                new SecurityBytes(identity, 32), parents, BigInteger.ZERO, new SecurityBytes(key, 65));
        for (var bytes : List.of(id, identity, author, parent, key, token.objectId().bytes(), token.tokenId().bytes(),
                token.authorDeviceId().bytes(), token.parents().get(0).bytes(), device.deviceId().bytes(),
                device.publicKeyX963().bytes(), device.parents().get(0).bytes())) { Arrays.fill(bytes, (byte) 99); }
        parents.clear();
        assertEquals(expectedToken, token); assertEquals(expectedDevice, device);
        assertThrows(UnsupportedOperationException.class, () -> token.parents().clear());
        assertThrows(UnsupportedOperationException.class, () -> device.parents().clear());

        var c = fixture(FIXTURES.get(4));
        byte[] encrypted = c.data().field("crypto").field("object_hex").hex();
        byte[] expected = encrypted.clone();
        var opened = EnvelopeReader.open(c.data().field("crypto").field("object_id").string(), encrypted, ProvenanceTest.root(c));
        Arrays.fill(encrypted, (byte) 0); // Mutation even before projection must be harmless.
        Arrays.fill(opened.exactObjectBytes(), (byte) 0);
        var unscoped = (OpaqueUnscopedRecord) observe(opened).record();
        Arrays.fill(unscoped.exactObjectBytes().bytes(), (byte) 0);
        assertArrayEquals(expected, unscoped.exactObjectBytes().bytes());
        assertArrayEquals(expected, opened.exactObjectBytes());
        assertNotEquals(new SecurityBytes(new byte[1024], 1024), unscoped.exactObjectBytes());
    }

    @Test
    void arrivalOrderAndEmptyLaterBatchDoNotChangeKnowledge() throws Exception {
        var forward = DurableKnowledgeState.establishedEmpty();
        var reverse = DurableKnowledgeState.establishedEmpty();
        for (String fixture : FIXTURES) { forward = learn(forward, observe(open(fixture(fixture)))); }
        for (int i = FIXTURES.size() - 1; i >= 0; i--) { reverse = learn(reverse, observe(open(fixture(FIXTURES.get(i))))); }
        assertEquals(forward.records(), reverse.records());
        var before = forward.records();
        // A later empty observation batch has nothing to commit; no snapshot replacement API exists.
        for (AuthenticatedObservation absentBatch : List.<AuthenticatedObservation>of()) { forward = learn(forward, absentBatch); }
        assertEquals(before, forward.records());
        assertEquals(5, forward.size());
        assertThrows(UnsupportedOperationException.class, reverse.records()::clear);
        for (var record : forward.records().values()) {
            for (var failure : DurableKnowledgeState.CurrentStorageFailure.values()) {
                assertSame(forward, forward.currentStorageFailure(record.objectId(), failure));
            }
        }
        assertEquals(LOCAL_CONTINUITY_KNOWN, forward.continuity());
    }

    @Test
    void benignFailuresRetainKnownNode() throws Exception {
        var reasons = List.of(DurableKnowledgeState.CurrentStorageFailure.ABSENT,
                DurableKnowledgeState.CurrentStorageFailure.UNREADABLE,
                DurableKnowledgeState.CurrentStorageFailure.WRONG_LENGTH,
                DurableKnowledgeState.CurrentStorageFailure.AEAD,
                DurableKnowledgeState.CurrentStorageFailure.PADDING,
                DurableKnowledgeState.CurrentStorageFailure.OBJECT_ID);
        assertEquals(reasons, List.of(DurableKnowledgeState.CurrentStorageFailure.values()));
        var observation = observe(open(fixture(FIXTURES.get(0))));
        var state = learn(DurableKnowledgeState.establishedEmpty(), observation);
        for (var reason : reasons) {
            var result = state.currentStorageFailure(observation.record().objectId(), reason);
            assertEquals(state.records(), result.records());
            assertEquals(LOCAL_CONTINUITY_KNOWN, result.continuity());
        }
    }

    @Test
    void authenticatedInvalidSemanticAtKnownIdBreaksContinuity() throws Exception {
        var c = ProvenanceTest.token();
        // A real authenticated invalid supported body under its own correctly computed ID.
        var invalid = ProvenanceTest.authenticate(
                TlvTestBytes.replace(c.semanticBytes(), 0x0103, new byte[]{99}), ProvenanceTest.root(c));
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_INVALID_STRUCTURE, invalid.status());
        assertNotNull(invalid.objectId());
        assertTrue(AuthenticatedObservation.opaque(invalid).isEmpty());
        var original = (KnownTokenNode) observe(open(c)).record();
        assertNotEquals(original.objectId(), invalid.objectId());
        // Deliberately inconsistent durable memory at that ID: not a second authenticated
        // object, not a real keyed-ID collision, and no weakened cryptographic primitive.
        var remembered = new KnownTokenNode(invalid.objectId(), original.objectVersion(),
                original.semanticStatus(), original.tokenId(), original.parents(),
                original.authorDeviceId(), original.authorTime());
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(remembered, COMMITTED).state();
        var empty = DurableKnowledgeState.establishedEmpty();
        assertSame(empty, empty.authenticatedInvalidSemantic(invalid.objectId()));
        var result = state.authenticatedInvalidSemantic(invalid.objectId());
        assertEquals(LOCAL_CONTINUITY_UNKNOWN, result.continuity());
        assertEquals(state.records(), result.records());
    }

    @Test
    void unsignedAuthorTimesAndCanonicalParentOrderArePreserved() throws Exception {
        for (String name : FIXTURES.subList(0, 4)) {
            var c = fixture(name);
            for (BigInteger time : List.of(BigInteger.ZERO, BigInteger.ONE.shiftLeft(63), BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE))) {
                byte[] raw = new byte[8]; byte[] encoded = time.toByteArray();
                System.arraycopy(encoded, Math.max(0, encoded.length - 8), raw, Math.max(0, 8 - encoded.length), Math.min(8, encoded.length));
                // Future tails deliberately are not TLV: replace only their frozen prefix.
                var opened = open(c);
                byte[] semantic = c.semanticBytes();
                int end = opened.routing().prefixLength();
                byte[] prefix = TlvTestBytes.replace(Arrays.copyOf(semantic, end), 0x0006, raw);
                var record = observe(ProvenanceTest.authenticate(TlvTestBytes.join(prefix, Arrays.copyOfRange(semantic, end, semantic.length)),
                        ProvenanceTest.root(c))).record();
                assertEquals(time, record instanceof KnownTokenNode t ? t.authorTime() : ((KnownDeviceNode) record).authorTime());
            }
        }
    }

    @Test
    void impossibleCollisionSeamChecksEveryImmutableTokenFieldAndCrossKind() throws Exception {
        var token = (KnownTokenNode) observe(open(fixture(FIXTURES.get(0)))).record();
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(token, COMMITTED).state();
        var different = new SecurityBytes(new byte[32], 32);
        var changed = List.<DurableRecord>of(
                new KnownTokenNode(token.objectId(), 2, SemanticStatus.OPAQUE_ROUTABLE, token.tokenId(), token.parents(), token.authorDeviceId(), token.authorTime()),
                new KnownTokenNode(token.objectId(), 1, token.semanticStatus(), different, token.parents(), token.authorDeviceId(), token.authorTime()),
                new KnownTokenNode(token.objectId(), 1, token.semanticStatus(), token.tokenId(), List.of(), token.authorDeviceId(), token.authorTime()),
                new KnownTokenNode(token.objectId(), 1, token.semanticStatus(), token.tokenId(), token.parents(), different, token.authorTime()),
                new KnownTokenNode(token.objectId(), 1, token.semanticStatus(), token.tokenId(), token.parents(), token.authorDeviceId(), token.authorTime().add(BigInteger.ONE)),
                new KnownDeviceNode(token.objectId(), 1, SemanticStatus.SUPPORTED_VALID, different, List.of(), BigInteger.ZERO, new SecurityBytes(new byte[65], 65)));
        for (var incompatible : changed) {
            var result = state.afterRecordPersistence(incompatible, COMMITTED);
            assertEquals(LOCAL_CONTINUITY_UNKNOWN, result.state().continuity());
            assertEquals(DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN, result.outcome());
            assertEquals(state.records(), result.state().records());
            assertEquals(LOCAL_CONTINUITY_UNKNOWN, result.state().afterRecordPersistence(token, COMMITTED).state().continuity());
        }
        assertEquals(LOCAL_CONTINUITY_KNOWN, state.continuity());
    }

    @Test
    void deviceKeyAndUnscopedExactByteMismatchesFailButFutureReclassificationIsDeferred() throws Exception {
        var d = (KnownDeviceNode) observe(open(fixture(FIXTURES.get(1)))).record();
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(d, COMMITTED).state();
        byte[] key = d.publicKeyX963().bytes(); key[64] ^= 1;
        var mismatch = new KnownDeviceNode(d.objectId(), d.objectVersion(), d.semanticStatus(), d.deviceId(), d.parents(), d.authorTime(), new SecurityBytes(key, 65));
        assertEquals(LOCAL_CONTINUITY_UNKNOWN, state.afterRecordPersistence(mismatch, COMMITTED).state().continuity());
        var u = (OpaqueUnscopedRecord) observe(open(fixture(FIXTURES.get(4)))).record();
        state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(u, COMMITTED).state();
        byte[] bytes = u.exactObjectBytes().bytes(); bytes[1023] ^= 1;
        assertEquals(LOCAL_CONTINUITY_UNKNOWN, state.afterRecordPersistence(new OpaqueUnscopedRecord(u.objectId(), new SecurityBytes(bytes, 1024)), COMMITTED).state().continuity());
        var scoped = new KnownDeviceNode(u.objectId(), d.objectVersion(), d.semanticStatus(), d.deviceId(), d.parents(), d.authorTime(), d.publicKeyX963());
        var result = state.afterRecordPersistence(scoped, COMMITTED);
        assertEquals(RECLASSIFICATION_REQUIRED, result.outcome());
        assertSame(state, result.state());
        assertEquals(LOCAL_CONTINUITY_KNOWN, result.state().continuity());
    }

    @Test
    void persistenceFailureNeverClaimsInsertionAndFlagsRemainSticky() throws Exception {
        for (String name : FIXTURES) {
            var observation = observe(open(fixture(name)));
            var empty = DurableKnowledgeState.establishedEmpty();
            var failed = empty.afterPersistence(observation, FAILED);
            assertEquals(PERSISTENCE_BLOCKED, failed.outcome());
            assertTrue(failed.state().knowledgePersistenceBlocked());
            assertEquals(0, failed.state().size());
            assertNull(failed.state().record(observation.record().objectId()));
            assertFalse(empty.knowledgePersistenceBlocked());
            var unknown = failed.state().localSecurityMemoryCorruption();
            var later = unknown.afterPersistence(observation, COMMITTED).state();
            assertTrue(later.knowledgePersistenceBlocked());
            assertEquals(LOCAL_CONTINUITY_UNKNOWN, later.continuity());
            assertEquals(1, later.size());
        }
    }

    @Test
    void deviceEqualityIncludesEveryRoutingFieldAndOpaqueVersion() throws Exception {
        var d = (KnownDeviceNode) observe(open(fixture(FIXTURES.get(1)))).record();
        var different = new SecurityBytes(new byte[32], 32);
        var changes = List.of(
                new KnownDeviceNode(d.objectId(), 2, SemanticStatus.OPAQUE_ROUTABLE, d.deviceId(), d.parents(), d.authorTime(), null),
                new KnownDeviceNode(d.objectId(), 1, d.semanticStatus(), different, d.parents(), d.authorTime(), d.publicKeyX963()),
                new KnownDeviceNode(d.objectId(), 1, d.semanticStatus(), d.deviceId(), List.of(d.objectId()), d.authorTime(), d.publicKeyX963()),
                new KnownDeviceNode(d.objectId(), 1, d.semanticStatus(), d.deviceId(), d.parents(), d.authorTime().add(BigInteger.ONE), d.publicKeyX963()));
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(d, COMMITTED).state();
        for (var changed : changes) {
            var result = state.afterRecordPersistence(changed, COMMITTED);
            assertEquals(LOCAL_CONTINUITY_UNKNOWN, result.state().continuity());
            assertEquals(d, result.state().record(d.objectId()));
        }
        var opaque = changes.get(0);
        var anotherVersion = new KnownDeviceNode(d.objectId(), 3, SemanticStatus.OPAQUE_ROUTABLE,
                d.deviceId(), d.parents(), d.authorTime(), null);
        assertNotEquals(opaque, anotherVersion);
        assertEquals(LOCAL_CONTINUITY_UNKNOWN, DurableKnowledgeState.establishedEmpty()
                .afterRecordPersistence(opaque, COMMITTED).state()
                .afterRecordPersistence(anotherVersion, COMMITTED).state().continuity());
    }

    @Test
    void parentClaimsAreOrderedImmutableFactsEvenWhenInterpretationWouldBeInvalid() {
        byte[] first = new byte[32], second = new byte[32];
        first[31] = 1; second[31] = 2;
        var a = new ObjectId(first); var b = new ObjectId(second);
        var parents = new ArrayList<>(List.of(a, b));
        var token = new KnownTokenNode(a, 2, SemanticStatus.OPAQUE_ROUTABLE,
                new SecurityBytes(first, 32), parents, new SecurityBytes(second, 32), BigInteger.ZERO);
        // Self-parent plus a wrong-kind parent: this milestone stores, but never resolves, claims.
        var device = new KnownDeviceNode(b, 2, SemanticStatus.OPAQUE_ROUTABLE,
                new SecurityBytes(second, 32), List.of(a), BigInteger.ZERO, null);
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(token, COMMITTED).state()
                .afterRecordPersistence(device, COMMITTED).state();
        parents.clear(); Arrays.fill(first, (byte) 99); Arrays.fill(second, (byte) 99);
        assertEquals(List.of(a, b), ((KnownTokenNode) state.record(a)).parents());
        assertEquals(LOCAL_CONTINUITY_KNOWN, state.continuity());
        assertThrows(IllegalArgumentException.class, () -> new KnownTokenNode(a, 2, SemanticStatus.OPAQUE_ROUTABLE,
                token.tokenId(), List.of(b, a), token.authorDeviceId(), BigInteger.ZERO));
    }

    @Test
    void identityIndexKeepsOldSnapshotsAndHandlesSharedKeyPrefixes() {
        var state = DurableKnowledgeState.establishedEmpty();
        var expected = new java.util.HashMap<ObjectId, DurableRecord>();
        var snapshots = new ArrayList<DurableKnowledgeState>();
        for (int i = 0; i < 300; i++) {
            byte[] raw = new byte[32]; raw[30] = (byte) (i >>> 8); raw[31] = (byte) i;
            var id = new ObjectId(raw);
            var record = new KnownTokenNode(id, 1, SemanticStatus.SUPPORTED_VALID, new SecurityBytes(raw, 32),
                    List.of(), new SecurityBytes(new byte[32], 32), BigInteger.ZERO);
            snapshots.add(state);
            state = state.afterRecordPersistence(record, COMMITTED).state();
            expected.put(id, record);
            assertEquals(record, state.record(id));
        }
        assertEquals(expected, state.records());
        for (int i = 0; i < snapshots.size(); i++) {
            assertEquals(i, snapshots.get(i).size());
            assertEquals(i, snapshots.get(i).records().size());
        }
    }

    @Test
    void impossibleRecordsAreRejectedAndDetectedMemoryCorruptionIsExplicit() throws Exception {
        var t = (KnownTokenNode) observe(open(fixture(FIXTURES.get(0)))).record();
        assertThrows(IllegalArgumentException.class, () -> new KnownTokenNode(t.objectId(), 1, SemanticStatus.OPAQUE_ROUTABLE,
                t.tokenId(), t.parents(), t.authorDeviceId(), t.authorTime()));
        assertThrows(IllegalArgumentException.class, () -> new KnownTokenNode(t.objectId(), 1, t.semanticStatus(),
                t.tokenId(), t.parents(), t.authorDeviceId(), BigInteger.ONE.shiftLeft(64)));
        assertThrows(IllegalArgumentException.class, () -> new KnownTokenNode(t.objectId(), 1, t.semanticStatus(),
                t.tokenId(), List.of(t.objectId(), t.objectId()), t.authorDeviceId(), BigInteger.ZERO));
        var state = DurableKnowledgeState.establishedEmpty().afterRecordPersistence(t, COMMITTED).state();
        var unknown = state.localSecurityMemoryCorruption();
        assertEquals(LOCAL_CONTINUITY_UNKNOWN, unknown.continuity());
        assertEquals(state.records(), unknown.records());
    }
}
