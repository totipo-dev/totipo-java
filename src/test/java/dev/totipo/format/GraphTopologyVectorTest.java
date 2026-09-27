package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.KnowledgeVectorTest.symbolId;
import static dev.totipo.format.KnowledgeVectorTest.symbolicRecord;
import static dev.totipo.format.DurableKnowledgeState.PersistenceResult.COMMITTED;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** Explicit partial graph contract: never reads values, readiness or presentation results. */
class GraphTopologyVectorTest {
    private static final Set<String> SELECTED = Set.of(
            "v1.graph.sequential.001", "v1.graph.equal-concurrent.001",
            "v1.graph.conflicting-concurrent.001", "v1.graph.late-parent.001",
            "v1.graph.intermediate-disappears.001", "v1.graph.wrong-identity-parent.001",
            "v1.graph.cycle-integrity-failure.001", "v1.future.concurrent-supported-opaque.001",
            "v1.future.supported-descendant.001", "v1.future.version-does-not-order.001",
            "v1.future.unrelated-token.001", "v1.future.device-presentation.001",
            "v1.future.disappearance-retains-routing.001");

    @TestFactory
    List<DynamicTest> topologyFieldsOnly() throws Exception {
        var all = new ArrayList<>(VectorCaseLoader.graphCases());
        all.addAll(VectorCaseLoader.futureCases());
        var selected = all.stream().filter(c -> SELECTED.contains(c.id())).toList();
        assertEquals(SELECTED, selected.stream().map(Case::id).collect(Collectors.toSet()));
        return selected.stream().map(c -> DynamicTest.dynamicTest(c.id() + " [M2.1 PARTIAL]", () -> {
            execute(c);
            System.out.println(c.id() + " M2.1 topology PASS; value/readiness/warning/presentation DEFERRED");
        })).toList();
    }

    private static GraphTopology execute(Case c) {
        var state = DurableKnowledgeState.establishedEmpty();
        for (var step : c.data().field("graph").field("steps").array()) {
            switch (step.field("action").string()) {
                case "learn" -> {
                    var record = symbolicRecord(step.field("node"));
                    var update = state.afterRecordPersistence(record, COMMITTED);
                    boolean error = step.has("integrity_error") && step.field("integrity_error").bool();
                    assertEquals(error, update.outcome() == DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN);
                    state = update.state();
                    assertEquals(record, state.record(record.objectId())); // Cycle evidence is retained.
                    assertFalse(state.knowledgePersistenceBlocked());
                }
                case "disappear" -> state = state.currentStorageFailure(symbolId(step.field("id").string()),
                        DurableKnowledgeState.CurrentStorageFailure.ABSENT);
                case "query" -> {
                    var before = state.records();
                    var continuity = state.continuity();
                    var graph = new GraphTopology(state);
                    var expected = step.field("expect");
                    boolean failure = expected.field("integrity_failure").bool();
                    assertEquals(failure, graph.integrity() == GraphIntegrityStatus.RESOLVED_CYCLE);
                    assertEquals(failure, continuity == LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN);
                    var identity = new SecurityBytes(symbolId(step.field("query").field("identity").string()).bytes(), 32);
                    if (failure) {
                        // Portable [] accompanies integrity_failure, NOT authoritative empty state.
                        assertThrows(IllegalStateException.class, () -> graph.currentTokenHeads(identity));
                    } else {
                        var heads = expected.field("heads").array().stream().map(n -> symbolId(n.string())).collect(Collectors.toSet());
                        assertEquals(heads, graph.currentTokenHeads(identity), c.context());
                        assertEquals(heads, graph.currentTokenHeads(identity));
                        for (var a : heads) {
                            for (var b : heads) { assertEquals(!a.equals(b), graph.concurrent(a, b)); }
                        }
                        if (c.id().equals("v1.graph.late-parent.001")) {
                            assertEquals(state.record(symbolId("a")) == null ? ParentEdgeStatus.UNRESOLVED : ParentEdgeStatus.RESOLVED,
                                    graph.edgeStatus(symbolId("b"), symbolId("a")));
                        }
                        if (c.id().equals("v1.graph.intermediate-disappears.001")) {
                            assertTrue(graph.ancestor(symbolId("a"), symbolId("c")));
                        }
                        if (c.id().equals("v1.graph.wrong-identity-parent.001")) {
                            assertEquals(ParentEdgeStatus.REJECTED, graph.edgeStatus(symbolId("a"), symbolId("p")));
                            assertFalse(graph.ancestor(symbolId("p"), symbolId("a")));
                        }
                        if (step.field("query").has("device")) {
                            // Additional topology assertion inferred from this case's sole DEVICE node;
                            // the portable presentation field itself is deliberately not evaluated.
                            var device = new SecurityBytes(symbolId(step.field("query").field("device").string()).bytes(), 32);
                            assertEquals(Set.of(symbolId("d")), graph.currentDeviceHeads(device));
                        }
                    }
                    assertEquals(before, state.records());
                    assertEquals(continuity, state.continuity());
                }
                default -> fail("Unexpected action in selected M2.1 contract");
            }
        }
        return new GraphTopology(state);
    }

    @Test
    void equalAndConflictingValuesProduceExactlyTheSameTopology() throws Exception {
        var cases = VectorCaseLoader.graphCases();
        var equal = execute(cases.stream().filter(c -> c.id().equals("v1.graph.equal-concurrent.001")).findFirst().orElseThrow());
        var conflicting = execute(cases.stream().filter(c -> c.id().equals("v1.graph.conflicting-concurrent.001")).findFirst().orElseThrow());
        var token = new SecurityBytes(symbolId("T").bytes(), 32);
        assertEquals(equal.currentTokenHeads(token), conflicting.currentTokenHeads(token));
        for (String a : List.of("a", "b")) {
            assertEquals(equal.parentEdges(symbolId(a)), conflicting.parentEdges(symbolId(a)));
            for (String b : List.of("a", "b")) {
                assertEquals(equal.ancestor(symbolId(a), symbolId(b)), conflicting.ancestor(symbolId(a), symbolId(b)));
                assertEquals(equal.concurrent(symbolId(a), symbolId(b)), conflicting.concurrent(symbolId(a), symbolId(b)));
            }
        }
    }
}
