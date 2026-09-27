package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DurableKnowledgeState.PersistenceResult.*;
import static dev.totipo.format.LocalContinuityStatus.*;
import static dev.totipo.format.ParentEdgeStatus.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class GraphTopologyTest {
    static ObjectId id(int n) { return new ObjectId(ByteBuffer.allocate(32).putInt(n).array()); }
    static SecurityBytes identity(int n) { return new SecurityBytes(id(n).bytes(), 32); }
    static DurableRecord node(boolean token, int id, int identity, int version, int... parents) {
        var ps = java.util.Arrays.stream(parents).sorted().mapToObj(GraphTopologyTest::id).toList();
        var status = version == 1 ? SemanticStatus.SUPPORTED_VALID : SemanticStatus.OPAQUE_ROUTABLE;
        return token ? new KnownTokenNode(id(id), version, status, identity(identity), ps, identity(99), BigInteger.ZERO)
                : new KnownDeviceNode(id(id), version, status, identity(identity), ps, BigInteger.ZERO,
                        version == 1 ? new SecurityBytes(new byte[65], 65) : null);
    }
    static DurableKnowledgeState learn(DurableKnowledgeState state, DurableRecord record) {
        return state.afterRecordPersistence(record, COMMITTED).state();
    }
    static DurableKnowledgeState state(DurableRecord... records) {
        var state = DurableKnowledgeState.establishedEmpty();
        for (var record : records) { state = learn(state, record); }
        return state;
    }
    static Set<ObjectId> heads(GraphTopology g, boolean token, int identity) {
        return token ? g.currentTokenHeads(identity(identity)) : g.currentDeviceHeads(identity(identity));
    }

    @TestFactory
    List<DynamicTest> exactEdgeClassificationAndLateArrivalInBothFamilies() {
        var tests = new ArrayList<DynamicTest>();
        for (boolean token : List.of(true, false)) {
            var possibleParents = List.of(node(token, 1, 10, 1), node(token, 1, 10, 2),
                    node(token, 1, 11, 1), node(!token, 1, 10, 1),
                    new OpaqueUnscopedRecord(id(1), new SecurityBytes(new byte[1024], 1024)));
            for (int i = 0; i < possibleParents.size(); i++) {
                var parent = possibleParents.get(i);
                var expected = List.of(RESOLVED, RESOLVED, REJECTED, REJECTED, UNRESOLVED).get(i);
                tests.add(DynamicTest.dynamicTest((token ? "TOKEN" : "DEVICE") + " parent " + i, () -> {
                    var child = node(token, 2, 10, 1, 1);
                    var before = state(child);
                    var old = new GraphTopology(before);
                    assertEquals(UNRESOLVED, old.edgeStatus(id(2), id(1)));
                    assertEquals(Set.of(id(2)), heads(old, token, 10));
                    assertFalse(old.ancestor(id(1), id(2)));
                    for (var failure : DurableKnowledgeState.CurrentStorageFailure.values()) {
                        assertSame(before, before.currentStorageFailure(id(1), failure));
                    }
                    assertSame(before, before.authenticatedInvalidSemantic(id(1)));
                    var after = learn(before, parent);
                    var graph = new GraphTopology(after);
                    assertEquals(expected, graph.edgeStatus(id(2), id(1)));
                    assertEquals(expected == RESOLVED, graph.ancestor(id(1), id(2)));
                    assertEquals(Set.of(id(2)), heads(graph, token, 10));
                    assertEquals(LOCAL_CONTINUITY_KNOWN, after.continuity());
                    assertSame(child, after.record(id(2)));
                    assertEquals(UNRESOLVED, old.edgeStatus(id(2), id(1)));
                    assertEquals(1, before.size());
                    if (parent instanceof OpaqueUnscopedRecord) {
                        assertTrue(heads(graph, !token, 10).isEmpty());
                        assertTrue(graph.parentEdges(id(1)).isEmpty());
                    }
                }));
            }
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> headsAncestryConcurrencyAndDisappearance() {
        return List.of(true, false).stream().map(token -> DynamicTest.dynamicTest("family " + token, () -> {
            var state = DurableKnowledgeState.establishedEmpty();
            assertTrue(heads(new GraphTopology(state), token, 10).isEmpty());
            state = learn(state, node(token, 1, 10, 1));
            assertEquals(Set.of(id(1)), heads(new GraphTopology(state), token, 10));
            state = learn(state, node(token, 2, 10, 1, 1));
            var graph = new GraphTopology(state);
            assertTrue(graph.ancestor(id(1), id(2)));
            assertFalse(graph.ancestor(id(2), id(1)));
            assertFalse(graph.concurrent(id(1), id(2)));
            assertEquals(Set.of(id(2)), heads(graph, token, 10));
            state = learn(state, node(token, 3, 10, 2, 2));
            assertEquals(Set.of(id(3)), heads(new GraphTopology(state), token, 10));
            state = learn(state, node(token, 4, 10, 1, 3));
            state = learn(state, node(token, 5, 10, 2));
            state = learn(state, node(token, 6, 11, 1, 4));
            var before = state.records();
            for (var failure : DurableKnowledgeState.CurrentStorageFailure.values()) {
                state = state.currentStorageFailure(id(3), failure);
                state = state.currentStorageFailure(id(4), failure);
            }
            graph = new GraphTopology(state);
            for (int a = 1; a <= 4; a++) {
                assertFalse(graph.ancestor(id(a), id(a)));
                assertFalse(graph.concurrent(id(a), id(a)));
                for (int b = a + 1; b <= 4; b++) { assertTrue(graph.ancestor(id(a), id(b))); }
            }
            assertTrue(graph.concurrent(id(4), id(5)));
            assertTrue(graph.concurrent(id(5), id(4)));
            assertFalse(graph.concurrent(id(4), id(6)));
            assertFalse(graph.ancestor(id(4), id(6)));
            assertEquals(REJECTED, graph.edgeStatus(id(6), id(4)));
            assertEquals(Set.of(id(4), id(5)), heads(graph, token, 10));
            assertEquals(Set.of(id(6)), heads(graph, token, 11));
            for (int repeat = 0; repeat < 3; repeat++) {
                assertEquals(Set.of(id(4), id(5)), heads(graph, token, 10));
                assertTrue(graph.ancestor(id(1), id(4)));
            }
            assertEquals(before, state.records());
            assertEquals(LOCAL_CONTINUITY_KNOWN, state.continuity());
            var immutableGraph = graph;
            assertThrows(UnsupportedOperationException.class, () -> heads(immutableGraph, token, 10).clear());
            assertThrows(UnsupportedOperationException.class, () -> immutableGraph.parentEdges(id(4)).clear());
            assertThrows(IllegalArgumentException.class, () -> immutableGraph.edgeStatus(id(4), id(1)));
        })).toList();
    }

    @Test
    void independentRootsIgnoreVersionTimeAuthorAndObjectIdOrder() {
        var a = new KnownTokenNode(id(9), 1, SemanticStatus.SUPPORTED_VALID, identity(10), List.of(),
                identity(100), BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE));
        var b = node(true, 1, 10, 2);
        var graph = new GraphTopology(state(a, b));
        assertTrue(graph.concurrent(a.objectId(), b.objectId()));
        assertEquals(Set.of(id(9), id(1)), graph.currentTokenHeads(identity(10)));
        var devices = new GraphTopology(state(node(false, 1, 10, 1), node(false, 2, 10, 1)));
        assertTrue(devices.concurrent(id(1), id(2)));
        assertEquals(Set.of(id(1), id(2)), devices.currentDeviceHeads(identity(10)));
        var tokens = new GraphTopology(state(node(true, 1, 10, 1), node(true, 2, 10, 1)));
        assertTrue(tokens.concurrent(id(1), id(2)));
        assertEquals(Set.of(id(1), id(2)), tokens.currentTokenHeads(identity(10)));
    }

    @TestFactory
    List<DynamicTest> defensiveCyclesRetainCommittedEvidence() {
        var tests = new ArrayList<DynamicTest>();
        for (boolean token : List.of(true, false)) {
            for (int length : List.of(1, 2, 3)) {
                for (int version : List.of(1, 2)) {
                    tests.add(DynamicTest.dynamicTest("cycle " + token + "/" + length + "/" + version, () -> {
                        var state = DurableKnowledgeState.establishedEmpty();
                        var raw = new HashMap<ObjectId, DurableRecord>();
                        for (int i = 1; i <= length; i++) {
                            var record = node(token, i, 10, i == length ? version : 1, i == length ? 1 : i + 1);
                            raw.put(record.objectId(), record);
                            var before = state;
                            var failed = before.afterRecordPersistence(record, FAILED);
                            assertEquals(before.records(), failed.state().records());
                            assertEquals(before.continuity(), failed.state().continuity());
                            var update = state.afterRecordPersistence(record, COMMITTED);
                            state = update.state();
                            assertEquals(i, state.size());
                            assertEquals(i == length ? LOCAL_CONTINUITY_UNKNOWN : LOCAL_CONTINUITY_KNOWN, state.continuity());
                            assertEquals(i == length ? DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN
                                    : DurableKnowledgeState.Outcome.INSERTED, update.outcome());
                            assertFalse(state.knowledgePersistenceBlocked());
                            if (i < length) { assertEquals(GraphIntegrityStatus.ACYCLIC, new GraphTopology(state).integrity()); }
                        }
                        var graph = new GraphTopology(state);
                        assertEquals(raw, state.records());
                        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE, graph.integrity());
                        // Independently validate arbitrary trusted records, with no insertion flag.
                        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE, new GraphTopology(raw).integrity());
                        assertThrows(IllegalStateException.class, () -> heads(graph, token, 10));
                        assertThrows(IllegalStateException.class, () -> graph.ancestor(id(1), id(2)));
                        assertThrows(IllegalStateException.class, () -> graph.concurrent(id(1), id(2)));
                        assertEquals(RESOLVED, graph.parentEdges(id(1)).get(0).status());
                        assertEquals(LOCAL_CONTINUITY_UNKNOWN, learn(state, node(token, 9, 11, 1)).continuity());
                    }));
                }
            }
        }
        return tests;
    }

    @Test
    void rejectedWouldBeCyclesAreNotTraversed() {
        for (boolean token : List.of(true, false)) {
            for (boolean wrongType : List.of(true, false)) {
                var state = state(node(token, 1, 10, 1, 2), node(wrongType ? !token : token, 2, wrongType ? 10 : 11, 2, 1));
                var graph = new GraphTopology(state);
                assertEquals(REJECTED, graph.edgeStatus(id(1), id(2)));
                assertEquals(REJECTED, graph.edgeStatus(id(2), id(1)));
                assertEquals(GraphIntegrityStatus.ACYCLIC, graph.integrity());
                assertEquals(LOCAL_CONTINUITY_KNOWN, state.continuity());
                assertFalse(graph.ancestor(id(1), id(2)));
                assertFalse(graph.concurrent(id(1), id(2)));
                assertEquals(Set.of(id(1)), heads(graph, token, 10));
            }
        }
    }

    @Test
    void allArrivalPermutationsHaveIdenticalTopology() {
        for (boolean token : List.of(true, false)) {
            var nodes = List.of(node(token, 1, 10, 1), node(token, 2, 10, 2, 1),
                    node(token, 3, 10, 1, 1), node(token, 4, 10, 1, 2, 3));
            for (int size : List.of(3, 4)) {
                var baseline = new GraphTopology(state(nodes.subList(0, size).toArray(DurableRecord[]::new)));
                int count = 0;
                for (int a = 0; a < size; a++) {
                    for (int b = 0; b < size; b++) {
                        for (int c = 0; c < size; c++) {
                            for (int d = 0; d < (size == 3 ? 1 : size); d++) {
                                var order = size == 3 ? List.of(a, b, c) : List.of(a, b, c, d);
                                if (Set.copyOf(order).size() != size) { continue; }
                                count++;
                                var state = DurableKnowledgeState.establishedEmpty();
                                for (int i : order) { state = learn(state, nodes.get(i)); }
                                var graph = new GraphTopology(state);
                                assertEquals(baseline.integrity(), graph.integrity());
                                assertEquals(LOCAL_CONTINUITY_KNOWN, state.continuity());
                                assertEquals(heads(baseline, token, 10), heads(graph, token, 10));
                                for (int i = 1; i <= size; i++) {
                                    assertEquals(baseline.parentEdges(id(i)), graph.parentEdges(id(i)));
                                    for (int j = 1; j <= size; j++) {
                                        assertEquals(baseline.ancestor(id(i), id(j)), graph.ancestor(id(i), id(j)));
                                        assertEquals(baseline.concurrent(id(i), id(j)), graph.concurrent(id(i), id(j)));
                                    }
                                }
                            }
                        }
                    }
                }
                assertEquals(size == 3 ? 6 : 24, count);
            }
        }
    }

    @Test
    void deviceHeadsAndEdgesDoNotDependOnProvenance() throws Exception {
        var fixture = ProvenanceTest.device();
        var root = ProvenanceTest.root(fixture);
        var valid = AssertionValidator.validate(DurableKnowledgeTest.open(fixture)).object();
        assertEquals(ProvenanceStatus.VERIFIED, ProvenanceTest.evaluate(valid, root, ProvenanceTest.key(fixture)));
        var observation = AuthenticatedObservation.supported(valid);
        var state = DurableKnowledgeState.establishedEmpty().afterPersistence(observation, COMMITTED).state();
        var node = (KnownDeviceNode) observation.record();
        assertEquals(ProvenanceStatus.UNRESOLVED, ProvenanceEvaluator.evaluate(valid, root,
                VerificationKeyMaterial.temporarilyUnavailable()));
        assertEquals(Set.of(node.objectId()), new GraphTopology(state).currentDeviceHeads(node.deviceId()));
        var rejected = ProvenanceTest.valid(TlvTestBytes.replace(fixture.semanticBytes(), 0xff01, new byte[0]), root);
        assertEquals(ProvenanceStatus.REJECTED, ProvenanceTest.evaluate(rejected, root));
        var rejectedObservation = AuthenticatedObservation.supported(rejected);
        state = state.afterPersistence(rejectedObservation, COMMITTED).state();
        var graph = new GraphTopology(state);
        assertEquals(Set.of(node.objectId(), rejected.objectId()), graph.currentDeviceHeads(node.deviceId()));
        assertTrue(graph.concurrent(node.objectId(), rejected.objectId()));
        // Symbolic child checks topology of both actual projected records; no signing claim.
        var parents = java.util.stream.Stream.of(node.objectId(), rejected.objectId())
                .sorted((a, b) -> java.util.Arrays.compareUnsigned(a.bytes(), b.bytes())).toList();
        var child = new KnownDeviceNode(id(1), 2, SemanticStatus.OPAQUE_ROUTABLE, node.deviceId(), parents,
                BigInteger.ZERO, null);
        graph = new GraphTopology(learn(state, child));
        assertEquals(Set.of(child.objectId()), graph.currentDeviceHeads(node.deviceId()));
        for (var parent : parents) { assertEquals(RESOLVED, graph.edgeStatus(child.objectId(), parent)); }
    }

    @Test
    void longChainAndLateCycleDoNotDependOnJavaStackDepth() {
        int length = 20_000;
        var state = DurableKnowledgeState.establishedEmpty();
        // Learn forward references: each insertion has one unresolved outgoing edge.
        for (int i = 1; i < length; i++) { state = learn(state, node(true, i, 10, 1, i + 1)); }
        var before = state;
        var acyclic = learn(before, node(true, length, 10, 2));
        var graph = new GraphTopology(acyclic);
        assertTrue(graph.ancestor(id(length), id(1)));
        assertFalse(graph.ancestor(id(1), id(length)));
        assertEquals(Set.of(id(1)), graph.currentTokenHeads(identity(10)));
        var cyclic = learn(before, node(true, length, 10, 2, 1));
        assertEquals(LOCAL_CONTINUITY_UNKNOWN, cyclic.continuity());
        assertEquals(length, cyclic.size());
        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE, new GraphTopology(cyclic).integrity());
    }
}
