package dev.totipo.format;

import static dev.totipo.format.TokenValueFixtures.*;
import static dev.totipo.format.CurrentTokenValueState.*;
import static dev.totipo.format.GraphTopologyTest.state;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class CurrentTokenValueTest {
    @Test
    void emptySingletonEqualAndConflictingHeads() throws Exception {
        assertEquals(NO_KNOWN_CURRENT_STATE, evaluate(graph()).state());
        var a = readable(1, value());
        var b = readable(2, value());
        var c = readable(3, value(1, "Example", "bob", 1, 6, 30, (byte) 42));
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, evaluate(graph(a), a).state());
        var graph = graph(a, b);
        var result = evaluate(graph, a, b, a);
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, result.state());
        assertEquals(Set.of(a.objectId(), b.objectId()), result.readableSupportedHeadIds());
        assertEquals(Set.of(value()), result.distinctReadableValues());
        assertEquals(result.currentHeadIds(), graph.currentTokenHeads(TOKEN));
        assertEquals(WHOLE_STATE_CONFLICT, evaluate(graph(a, c), a, c).state());
    }

    @Test
    void opaqueAndUnavailablePrecedenceRetainsEveryPartition() throws Exception {
        var a = readable(1, value());
        var b = readable(2, value(1, "Other", "alice", 1, 6, 30, (byte) 42));
        var c = readable(3, value());
        var opaque = opaque(4);
        assertEquals(VALUE_INCOMPLETE_OPAQUE, evaluate(new GraphTopology(state(a.routing(), opaque)), a).state());
        for (var supplied : List.of(List.of(a), List.of(a, b))) {
            var g = new GraphTopology(state(a.routing(), b.routing(), c.routing(), opaque));
            var result = CurrentTokenValueEvaluator.evaluate(g, TOKEN, new CurrentReadableValues(g, supplied));
            assertEquals(VALUE_INCOMPLETE_OPAQUE, result.state());
            assertEquals(Set.of(opaque.objectId()), result.opaqueHeadIds());
            assertTrue(result.unavailableSupportedHeadIds().contains(c.objectId()));
            assertEquals(supplied.size(), result.distinctReadableValues().size());
            assertPartition(result);
            g = graph(a, b, c);
            result = CurrentTokenValueEvaluator.evaluate(g, TOKEN, new CurrentReadableValues(g, supplied));
            assertEquals(VALUE_INCOMPLETE_UNAVAILABLE, result.state());
            assertPartition(result);
        }
    }

    static void assertPartition(CurrentTokenValueView view) {
        var all = new java.util.HashSet<>(view.opaqueHeadIds());
        for (var id : view.unavailableSupportedHeadIds()) { assertTrue(all.add(id)); }
        for (var id : view.readableSupportedHeadIds()) { assertTrue(all.add(id)); }
        assertEquals(view.currentHeadIds(), all);
    }

    @Test
    void noAncestorFallbackAndAvailabilityChangesDoNotMutateTopology() throws Exception {
        var a = readable(1, value());
        var b = readable(2, value(), a.objectId());
        var durable = state(a.routing(), b.routing());
        var before = durable.records();
        var graph = new GraphTopology(durable);
        var complete = evaluate(graph, a, b);
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, complete.state());
        var missing = evaluate(graph, a);
        assertEquals(VALUE_INCOMPLETE_UNAVAILABLE, missing.state());
        assertEquals(Set.of(b.objectId()), missing.unavailableSupportedHeadIds());
        assertTrue(missing.distinctReadableValues().isEmpty());
        assertEquals(complete, evaluate(graph, a, b));
        assertEquals(complete.currentHeadIds(), missing.currentHeadIds());
        assertTrue(graph.ancestor(a.objectId(), b.objectId()));
        for (var failure : DurableKnowledgeState.CurrentStorageFailure.values()) {
            assertSame(durable, durable.currentStorageFailure(b.objectId(), failure));
            // Supplied evidence is a trusted exact local copy even after hostile remote failures.
            assertEquals(complete, evaluate(graph, a, b));
            assertEquals(missing, evaluate(graph, a));
        }
        assertEquals(before, durable.records());
    }

    @Test
    void lateParentChangesAncestryButNotReadableCurrentValue() throws Exception {
        var a = readable(1, value());
        var b = readable(2, value(), a.objectId());
        var before = graph(b);
        assertEquals(ParentEdgeStatus.UNRESOLVED, before.edgeStatus(b.objectId(), a.objectId()));
        var result = evaluate(before, b);
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, result.state());
        var after = graph(a, b);
        assertEquals(ParentEdgeStatus.RESOLVED, after.edgeStatus(b.objectId(), a.objectId()));
        assertEquals(result, evaluate(after, a, b));
    }

    @Test
    void supportedDescendantRemovesOpaqueFromCurrentPartition() throws Exception {
        var a = readable(1, value());
        var b = opaque(2, a.objectId());
        var c = readable(3, value(), b.objectId());
        var g = new GraphTopology(state(a.routing(), b, c.routing()));
        var result = evaluate(g, a, c);
        assertEquals(Set.of(c.objectId()), result.currentHeadIds());
        assertTrue(result.opaqueHeadIds().isEmpty());
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, result.state());
    }

    @TestFactory
    List<DynamicTest> eachValueFieldAloneCreatesConflict() {
        var variants = List.of(value(2, "Example", "alice", 1, 6, 30, (byte) 42),
                value(1, "Other", "alice", 1, 6, 30, (byte) 42),
                value(1, "Example", "bob", 1, 6, 30, (byte) 42),
                value(1, "Example", "alice", 2, 6, 30, (byte) 42),
                value(1, "Example", "alice", 1, 8, 30, (byte) 42),
                value(1, "Example", "alice", 1, 6, 60, (byte) 42),
                value(1, "Example", "alice", 1, 6, 30, (byte) 43));
        var names = List.of("STATUS", "ISSUER", "ACCOUNT", "ALGORITHM", "DIGITS", "PERIOD", "SECRET_BYTES");
        var tests = new ArrayList<DynamicTest>();
        for (int i = 0; i < variants.size(); i++) {
            var variant = variants.get(i);
            tests.add(DynamicTest.dynamicTest(names.get(i), () -> {
                assertNotEquals(value(), variant);
                var a = readable(1, value()); var b = readable(2, variant);
                var result = evaluate(graph(a, b), a, b);
                assertEquals(WHOLE_STATE_CONFLICT, result.state());
                assertEquals(2, result.distinctReadableValues().size());
            }));
        }
        return tests;
    }

    @Test
    void tombstonesRemainCompleteValues() throws Exception {
        var tombstone = value(2, "Example", "alice", 1, 6, 30, (byte) 42);
        var a = readable(1, tombstone); var b = readable(2, tombstone);
        var result = evaluate(graph(a, b), a, b);
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, result.state());
        assertEquals(Set.of(tombstone), result.distinctReadableValues());
        var c = readable(3, value(2, "Example", "alice", 1, 6, 30, (byte) 43));
        assertEquals(WHOLE_STATE_CONFLICT, evaluate(graph(a, c), a, c).state());
        var live = readable(4, value());
        assertEquals(WHOLE_STATE_CONFLICT, evaluate(graph(a, live), a, live).state());
    }

    @Test
    void exactUnicodeAndNoCaseOrWhitespaceNormalization() throws Exception {
        var equal = value(1, "é 日本", "Å 😀", 1, 6, 30, (byte) 42);
        var a = readable(1, equal); var b = readable(2, equal);
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, evaluate(graph(a, b), a, b).state());
        for (var other : List.of(value(1, "e\u0301 日本", "Å 😀", 1, 6, 30, (byte) 42),
                value(1, "é 日本", "A\u030a 😀", 1, 6, 30, (byte) 42),
                value(1, "É 日本", "Å 😀", 1, 6, 30, (byte) 42),
                value(1, "é 日本 ", "Å 😀", 1, 6, 30, (byte) 42))) {
            var c = readable(3, other);
            assertNotEquals(equal, other);
            assertEquals(WHOLE_STATE_CONFLICT, evaluate(graph(a, c), a, c).state());
        }
    }

    @Test
    void metadataAndProvenanceNeverCreateValueConflict() throws Exception {
        var fixture = ProvenanceTest.token();
        var original = ProvenanceTest.valid(fixture.semanticBytes(), ProvenanceTest.root(fixture));
        var a = ReadableTokenValue.supported(original);
        assertEquals(ProvenanceStatus.VERIFIED, ProvenanceTest.evaluate(original,
                ProvenanceTest.root(fixture), ProvenanceTest.key(fixture)));
        assertEquals(ProvenanceStatus.UNRESOLVED, ProvenanceTest.evaluate(original, ProvenanceTest.root(fixture)));
        // Each variant changes only one excluded semantic metadata field (and consequently OBJECT_ID).
        for (byte[] semantic : List.of(
                TlvTestBytes.replace(fixture.semanticBytes(), 0x0102, GraphTopologyTest.id(77).bytes()),
                TlvTestBytes.replace(fixture.semanticBytes(), 6, java.nio.ByteBuffer.allocate(8).putLong(-1L).array()),
                TlvTestBytes.replace(fixture.semanticBytes(), 0xff01, new byte[0]),
                semantic(1, a.tokenId(), List.of(GraphTopologyTest.id(123)), a.routing().authorDeviceId(),
                        a.routing().authorTime(), original.plaintext().signature(), a.value()))) {
            var assertion = ProvenanceTest.valid(semantic, ProvenanceTest.root(fixture));
            var b = ReadableTokenValue.supported(assertion);
            assertNotEquals(a.objectId(), b.objectId());
            assertEquals(a.value(), b.value());
            var g = graph(a, b);
            var result = CurrentTokenValueEvaluator.evaluate(g, a.tokenId(), new CurrentReadableValues(g, List.of(a, b)));
            assertEquals(SEMANTICALLY_UNAMBIGUOUS, result.state());
            assertEquals(2, result.currentHeadIds().size());
            assertEquals(1, result.distinctReadableValues().size());
        }
        byte[] bad = fixture.semanticBytes(); bad[bad.length - 1] ^= 1;
        var rejected = ProvenanceTest.valid(bad, ProvenanceTest.root(fixture));
        assertEquals(ProvenanceStatus.REJECTED, ProvenanceTest.evaluate(rejected,
                ProvenanceTest.root(fixture), ProvenanceTest.key(fixture)));
        var b = ReadableTokenValue.supported(rejected);
        var g = graph(a, b);
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, CurrentTokenValueEvaluator.evaluate(g, a.tokenId(),
                new CurrentReadableValues(g, List.of(a, b))).state());
        var unresolved = ProvenanceTest.valid(TlvTestBytes.replace(fixture.semanticBytes(), 0x0102,
                GraphTopologyTest.id(77).bytes()), ProvenanceTest.root(fixture));
        assertEquals(ProvenanceStatus.UNRESOLVED, ProvenanceTest.evaluate(unresolved,
                ProvenanceTest.root(fixture), ProvenanceTest.key(fixture)));
        var c = ReadableTokenValue.supported(unresolved);
        g = graph(a, b, c);
        var allStatuses = CurrentTokenValueEvaluator.evaluate(g, a.tokenId(), new CurrentReadableValues(g, List.of(a, b, c)));
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, allStatuses.state());
        assertEquals(3, allStatuses.readableSupportedHeadIds().size());
        assertEquals(Set.of(a.value()), allStatuses.distinctReadableValues());
    }

    @Test
    void exactPinnedEnvelopeBindsEvidenceAndOwnsItsValue() throws Exception {
        var fixture = ProvenanceTest.token();
        var crypto = fixture.data().field("crypto");
        byte[] bytes = crypto.field("object_hex").hex();
        var opened = EnvelopeReader.open(crypto.field("object_id").string(), bytes, ProvenanceTest.root(fixture));
        var assertion = AssertionValidator.validate(opened).object();
        var evidence = ReadableTokenValue.supported(assertion);
        assertEquals(crypto.field("object_id").string(), evidence.objectId().filename());
        assertEquals(AuthenticatedObservation.supported(assertion).record(), evidence.routing());
        var expected = evidence.value();
        java.util.Arrays.fill(bytes, (byte) 0);
        java.util.Arrays.fill(assertion.plaintext().token().credential().secret(), (byte) 0);
        java.util.Arrays.fill(evidence.value().credential().secret().bytes(), (byte) 0);
        assertEquals(expected, ReadableTokenValue.supported(assertion).value());
        var otherIdentity = readable(1, TOKEN, expected);
        assertNotEquals(evidence.tokenId(), otherIdentity.tokenId());
        assertEquals(evidence.value(), otherIdentity.value()); // TOKEN_ID is excluded too.
    }

    @Test
    void evidenceCannotBeCreatedFromDeviceAndDoesNotExposeSecrets() throws Exception {
        var d = ProvenanceTest.device();
        assertThrows(IllegalArgumentException.class, () -> ReadableTokenValue.supported(
                ProvenanceTest.valid(d.semanticBytes(), ProvenanceTest.root(d))));
        byte[] bytes = {42};
        var v = value(1, "Example", "alice", 1, 6, 30, bytes);
        bytes[0] = 0; v.credential().secret().bytes()[0] = 0;
        assertEquals(value(), v);
        assertEquals(value().hashCode(), v.hashCode());
        assertEquals("TokenValue[redacted]", v.toString());
        assertEquals("Credential[redacted]", v.credential().toString());
        var a = readable(1, v);
        var g = graph(a);
        var supplied = new ArrayList<>(List.of(a));
        var snapshot = new CurrentReadableValues(g, supplied);
        supplied.clear();
        var view = CurrentTokenValueEvaluator.evaluate(g, TOKEN, snapshot);
        for (Set<?> set : List.of(view.currentHeadIds(), view.opaqueHeadIds(), view.unavailableSupportedHeadIds(),
                view.readableSupportedHeadIds(), view.distinctReadableValues())) {
            assertThrows(UnsupportedOperationException.class, set::clear);
        }
        assertEquals(SEMANTICALLY_UNAMBIGUOUS, view.state());
        assertEquals(view, CurrentTokenValueEvaluator.evaluate(g, TOKEN, snapshot));
    }

    @Test
    void unrelatedEvidenceAndReadinessFlagsDoNotAffectDescriptiveState() throws Exception {
        var a = readable(1, value());
        var b = readable(2, GraphTopologyTest.identity(101), value(2, "Other", "bob", 3, 8, 60, (byte) 11));
        var durable = state(a.routing(), b.routing(), new OpaqueUnscopedRecord(GraphTopologyTest.id(5),
                new SecurityBytes(new byte[1024], 1024)));
        durable = durable.localSecurityMemoryCorruption().afterRecordPersistence(GraphTopologyTest.node(
                true, 7, 8, 1), DurableKnowledgeState.PersistenceResult.FAILED).state();
        assertTrue(durable.knowledgePersistenceBlocked());
        assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN, durable.continuity());
        var g = new GraphTopology(durable);
        assertEquals(evaluate(graph(a), a), evaluate(g, a, b));
        assertEquals(VALUE_INCOMPLETE_UNAVAILABLE, evaluate(g, b).state());
        assertEquals(NO_KNOWN_CURRENT_STATE, CurrentTokenValueEvaluator.evaluate(g,
                GraphTopologyTest.identity(999), new CurrentReadableValues(g, List.of(a, b))).state());
    }

    @Test
    void contradictionsAndCyclesFailExplicitly() throws Exception {
        var a = readable(1, value());
        var n = a.routing();
        var changes = List.of(
                new KnownTokenNode(n.objectId(), 1, n.semanticStatus(), GraphTopologyTest.identity(8), n.parents(), n.authorDeviceId(), n.authorTime()),
                new KnownTokenNode(n.objectId(), 2, SemanticStatus.OPAQUE_ROUTABLE, n.tokenId(), n.parents(), n.authorDeviceId(), n.authorTime()),
                new KnownTokenNode(n.objectId(), 1, n.semanticStatus(), n.tokenId(), List.of(GraphTopologyTest.id(8)), n.authorDeviceId(), n.authorTime()),
                new KnownTokenNode(n.objectId(), 1, n.semanticStatus(), n.tokenId(), n.parents(), GraphTopologyTest.identity(8), n.authorTime()),
                new KnownTokenNode(n.objectId(), 1, n.semanticStatus(), n.tokenId(), n.parents(), n.authorDeviceId(), BigInteger.TEN));
        for (var changed : changes) {
            var g = new GraphTopology(state(changed));
            assertThrows(IllegalStateException.class, () -> new CurrentReadableValues(g, List.of(a)));
        }
        assertThrows(IllegalStateException.class, () -> new CurrentReadableValues(graph(), List.of(a)));
        var g = graph(a);
        // Test-only reflection simulates an impossible authenticated-ID collision, without a production bypass.
        var constructor = ReadableTokenValue.class.getDeclaredConstructor(KnownTokenNode.class, TokenValue.class);
        constructor.setAccessible(true);
        var contradictory = constructor.newInstance(n, value(2, "Other", "bob", 1, 6, 30, (byte) 42));
        assertThrows(IllegalStateException.class, () -> new CurrentReadableValues(g, List.of(a, contradictory)));
        assertThrows(IllegalStateException.class, () -> CurrentTokenValueEvaluator.evaluate(g, TOKEN,
                new CurrentReadableValues(graph(a), List.of(a))));
        var cycle = new GraphTopology(state(GraphTopologyTest.node(true, 1, 100, 1, 2),
                GraphTopologyTest.node(true, 2, 100, 1, 1)));
        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE, cycle.integrity());
        assertThrows(IllegalStateException.class, () -> evaluate(cycle));
        assertThrows(IllegalStateException.class, () -> new CurrentTokenValueView(SEMANTICALLY_UNAMBIGUOUS,
                Set.of(a.objectId()), Set.of(), Set.of(), Set.of(), Set.of()));
        assertThrows(IllegalStateException.class, () -> new CurrentTokenValueView(VALUE_INCOMPLETE_OPAQUE,
                Set.of(a.objectId()), Set.of(a.objectId()), Set.of(a.objectId()), Set.of(), Set.of()));
    }
}
