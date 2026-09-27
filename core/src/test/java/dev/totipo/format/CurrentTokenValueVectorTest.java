package dev.totipo.format;

import static dev.totipo.format.TokenValueFixtures.*;
import static dev.totipo.format.KnowledgeVectorTest.symbolId;
import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Partial case evaluation: heads/value_state only, never operation or presentation expectations. */
class CurrentTokenValueVectorTest {
    private static final Set<String> SELECTED = Set.of(
            "v1.graph.sequential.001", "v1.graph.equal-concurrent.001",
            "v1.graph.conflicting-concurrent.001", "v1.graph.missing-current-value.001",
            "v1.graph.late-parent.001", "v1.graph.intermediate-disappears.001",
            "v1.graph.known-id-corrupt-bytes-retain-node.001",
            "v1.future.concurrent-supported-opaque.001", "v1.future.supported-descendant.001",
            "v1.future.version-does-not-order.001", "v1.future.unrelated-token.001",
            "v1.future.disappearance-retains-routing.001",
            "v1.timestamp.equal-value-different-times.001", "v1.timestamp.fold-common-time.001");

    @TestFactory
    List<DynamicTest> partialValueExpectations() throws Exception {
        var all = new ArrayList<>(VectorCaseLoader.graphCases());
        all.addAll(VectorCaseLoader.futureCases());
        all.addAll(VectorCaseLoader.timestampCases());
        var cases = all.stream().filter(c -> SELECTED.contains(c.id())).toList();
        assertEquals(SELECTED, cases.stream().map(Case::id).collect(Collectors.toSet()));
        return cases.stream().map(c -> DynamicTest.dynamicTest(c.id() + " [M2.2 PARTIAL]", () -> execute(c))).toList();
    }

    private static void execute(Case c) throws Exception {
        var steps = c.data().field("graph").field("steps").array();
        var adapter = new AuthenticatedSymbols(steps);
        var durable = DurableKnowledgeState.establishedEmpty();
        var available = new HashMap<ObjectId, ReadableTokenValue>();
        for (var step : steps) {
            switch (step.field("action").string()) {
                case "learn" -> {
                    var material = adapter.materialize(step.field("node").field("id").string());
                    durable = durable.afterPersistence(material.observation(),
                            DurableKnowledgeState.PersistenceResult.COMMITTED).state();
                    if (step.has("value")) { available.put(material.id(), material.readable()); }
                }
                case "disappear", "remote-unavailable" -> {
                    var id = adapter.materialize(step.field("id").string()).id();
                    var before = durable.records();
                    var failure = !step.has("reason") ? DurableKnowledgeState.CurrentStorageFailure.ABSENT
                            : switch (step.field("reason").string()) {
                                case "absent" -> DurableKnowledgeState.CurrentStorageFailure.ABSENT;
                                case "unreadable" -> DurableKnowledgeState.CurrentStorageFailure.UNREADABLE;
                                case "wrong-size" -> DurableKnowledgeState.CurrentStorageFailure.WRONG_LENGTH;
                                case "aead" -> DurableKnowledgeState.CurrentStorageFailure.AEAD;
                                case "padding" -> DurableKnowledgeState.CurrentStorageFailure.PADDING;
                                case "object-id" -> DurableKnowledgeState.CurrentStorageFailure.OBJECT_ID;
                                default -> throw new AssertionError("Unexpected reason");
                            };
                    durable = durable.currentStorageFailure(id, failure);
                    if (!step.has("flag") || !step.field("flag").bool()) { available.remove(id); }
                    assertEquals(before, durable.records());
                }
                case "state-query" -> {
                    // Only durable IDs/parents are checked. Authority and DEVICE presentation remain deferred.
                    var expected = step.field("state_expect");
                    assertEquals(adapter.ids(expected.field("known")), durable.records().keySet());
                    var record = (KnownTokenNode) durable.record(adapter.materialize(step.field("id").string()).id());
                    assertEquals(adapter.ids(expected.field("parents")), Set.copyOf(record.parents()));
                }
                case "query" -> {
                    var before = durable.records();
                    var g = new GraphTopology(durable);
                    var token = identity(step.field("query").field("identity").string());
                    var snapshot = new CurrentReadableValues(g, available.values());
                    var view = CurrentTokenValueEvaluator.evaluate(g, token, snapshot);
                    var expected = step.field("expect");
                    assertFalse(expected.field("integrity_failure").bool());
                    assertEquals(adapter.ids(expected.field("heads")), view.currentHeadIds(), c.context());
                    var state = switch (expected.field("value_state").string()) {
                        case "EMPTY" -> CurrentTokenValueState.NO_KNOWN_CURRENT_STATE;
                        case "UNAMBIGUOUS" -> CurrentTokenValueState.SEMANTICALLY_UNAMBIGUOUS;
                        case "CONFLICT" -> CurrentTokenValueState.WHOLE_STATE_CONFLICT;
                        default -> CurrentTokenValueState.valueOf(expected.field("value_state").string());
                    };
                    assertEquals(state, view.state(), c.context());
                    CurrentTokenValueTest.assertPartition(view);
                    if (c.id().equals("v1.graph.equal-concurrent.001")
                            || c.id().equals("v1.timestamp.equal-value-different-times.001")) {
                        assertEquals(2, view.readableSupportedHeadIds().size());
                        assertEquals(1, view.distinctReadableValues().size());
                    }
                    if (c.id().equals("v1.graph.conflicting-concurrent.001")) {
                        assertEquals(2, view.readableSupportedHeadIds().size());
                        assertEquals(2, view.distinctReadableValues().size());
                    }
                    if (c.id().equals("v1.graph.missing-current-value.001")) {
                        var a = adapter.materialize("a").id(); var b = adapter.materialize("b").id();
                        assertTrue(g.ancestor(a, b));
                        assertTrue(available.containsKey(a));
                        assertEquals(Set.of(b), view.unavailableSupportedHeadIds());
                        assertTrue(view.distinctReadableValues().isEmpty());
                    }
                    if (c.id().equals("v1.graph.late-parent.001")) {
                        var a = adapter.materialize("a").id(); var b = adapter.materialize("b").id();
                        assertEquals(durable.record(a) == null ? ParentEdgeStatus.UNRESOLVED : ParentEdgeStatus.RESOLVED,
                                g.edgeStatus(b, a));
                    }
                    if (c.id().equals("v1.graph.intermediate-disappears.001")) {
                        assertTrue(g.ancestor(adapter.materialize("a").id(), adapter.materialize("c").id()));
                    }
                    assertEquals(view, CurrentTokenValueEvaluator.evaluate(g, token, snapshot));
                    assertEquals(before, durable.records());
                    assertEquals(view.currentHeadIds(), g.currentTokenHeads(token));
                }
                default -> fail("Unexpected action in M2.2 partial contract");
            }
        }
        System.out.println(c.id() + " M2.2 PARTIAL heads/value_state PASS; ordinary/author/candidate/"
                + "candidate_warning/authoritative/discovery/presentation DEFERRED");
    }

    private static SecurityBytes identity(String symbol) { return new SecurityBytes(symbolId(symbol).bytes(), 32); }

    record Material(AuthenticatedObservation observation, ReadableTokenValue readable) {
        ObjectId id() { return observation.record().objectId(); }
    }

    /**
     * Symbolic DAG cases name identities, not encrypted bytes. Materialize them as test envelopes
     * before replay, mapping symbolic OBJECT_IDs to authenticated IDs consistently (including
     * late parents). No production evidence constructor is bypassed. Distinct semantic_digest
     * labels become distinct signature bytes; no provenance is claimed for these synthetic bytes.
     */
    static final class AuthenticatedSymbols {
        private final Map<String, Node> definitions = new HashMap<>();
        private final Map<String, Material> materialized = new HashMap<>();

        AuthenticatedSymbols(List<Node> steps) {
            for (var step : steps) {
                if (Set.of("learn", "persist-fails").contains(step.field("action").string())) {
                    definitions.putIfAbsent(step.field("node").field("id").string(), step);
                }
            }
        }

        Material materialize(String symbol) throws Exception {
            if (materialized.containsKey(symbol)) { return materialized.get(symbol); }
            var step = definitions.get(symbol);
            var node = step.field("node");
            assertEquals("TOKEN", node.field("type").string());
            var parents = new ArrayList<ObjectId>();
            if (!node.field("parents").isNull()) {
                for (var parent : node.field("parents").array()) { parents.add(materialize(parent.string()).id()); }
            }
            int version = node.field("version").integer().intValueExact();
            TokenValue v = null;
            if (step.has("value")) {
                var value = step.field("value");
                v = value(value.field("status").string().equals("LIVE") ? 1 : 2,
                        value.field("issuer").string(), value.field("account").string(),
                        value.field("algorithm").integer().intValueExact(), value.field("digits").integer().intValueExact(),
                        value.field("period").integer().longValueExact(), value.field("secret_hex").hex());
            }
            var bytes = semantic(version, identity(node.field("identity").string()), parents,
                    identity(node.has("author") ? node.field("author").string() : "author"),
                    node.field("author_time").integer(),
                    node.field("semantic_digest").string().getBytes(StandardCharsets.UTF_8), v);
            var opened = ProvenanceTest.authenticate(bytes, ROOT);
            Material result;
            if (version == 1) {
                var assertion = AssertionValidator.validate(opened).object();
                assertNotNull(assertion);
                result = new Material(AuthenticatedObservation.supported(assertion), ReadableTokenValue.supported(assertion));
                assertEquals(v, result.readable().value());
            } else {
                result = new Material(AuthenticatedObservation.opaque(opened).orElseThrow(), null);
            }
            assertEquals(node.field("class").string(), ((KnownTokenNode) result.observation().record()).semanticStatus().name());
            materialized.put(symbol, result);
            return result;
        }

        Set<ObjectId> ids(Node array) throws Exception {
            var result = new java.util.HashSet<ObjectId>();
            for (var node : array.array()) { assertTrue(result.add(materialize(node.string()).id())); }
            return Set.copyOf(result);
        }
    }
}
