package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DurableKnowledgeState.PersistenceResult.*;
import static dev.totipo.format.LocalContinuityStatus.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Partial contracts only: never claims full graph/future category conformance. */
class KnowledgeVectorTest {
    private static final Set<String> SELECTED = Set.of(
            "v1.graph.global-object-id-conflict.001", "v1.graph.reappearance.001",
            "v1.graph.reappearance-mismatch.001", "v1.graph.known-id-corrupt-bytes-retain-node.001",
            "v1.graph.local-security-memory-corruption.001", "v1.future.disappearance-retains-routing.001",
            "v1.future.unscoped-sticky.001", "v1.future.unscoped-retains-exact-object.001");

    @TestFactory
    List<DynamicTest> selectedM2KnowledgeExpectationsOnly() throws Exception {
        var all = new ArrayList<>(VectorCaseLoader.graphCases());
        all.addAll(VectorCaseLoader.futureCases());
        var selected = all.stream().filter(c -> SELECTED.contains(c.id())).toList();
        assertEquals(SELECTED, selected.stream().map(Case::id).collect(Collectors.toSet()));
        return selected.stream().map(c -> DynamicTest.dynamicTest(c.id() + " [M2.0 PARTIAL]", () -> {
            if (c.id().equals("v1.graph.known-id-corrupt-bytes-retain-node.001")) {
                // The pinned case has twelve unavailable events: each of these six reasons
                // with and without a trusted-copy flag. There is NO invalid-semantic trial.
                var reasons = c.data().field("graph").field("steps").array().stream()
                        .filter(s -> s.field("action").string().equals("remote-unavailable"))
                        .collect(Collectors.groupingBy(s -> s.field("reason").string(), Collectors.counting()));
                assertEquals(Map.of("absent", 2L, "unreadable", 2L, "wrong-size", 2L,
                        "aead", 2L, "padding", 2L, "object-id", 2L), reasons);
            }
            if (c.data().field("operation").string().equals("opaque-retention")) { retention(c); }
            else { symbolic(c); }
            System.out.println(c.id() + " M2.0 knowledge expectations PASS; heads/value/readiness/presentation "
                    + "DEFERRED; unscoped-sticky compatible reclassification and subsequent queries DEFERRED");
        })).toList();
    }

    private static void symbolic(Case c) {
        var state = DurableKnowledgeState.establishedEmpty();
        for (var step : c.data().field("graph").field("steps").array()) {
            switch (step.field("action").string()) {
                case "learn" -> {
                    var record = symbolicRecord(step.field("node"));
                    var before = state.record(record.objectId());
                    var update = state.afterRecordPersistence(record, COMMITTED);
                    boolean conflict = step.has("integrity_error") && step.field("integrity_error").bool();
                    assertEquals(conflict, update.outcome() == DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN, c.context());
                    state = update.state();
                    assertEquals(conflict ? before : record, state.record(record.objectId()));
                    if (before != null && !conflict) { assertEquals(DurableKnowledgeState.Outcome.UNCHANGED, update.outcome()); }
                }
                case "disappear", "remote-unavailable" -> {
                    var before = state.records();
                    var continuity = state.continuity();
                    var failure = step.has("reason") ? switch (step.field("reason").string()) {
                        case "absent" -> DurableKnowledgeState.CurrentStorageFailure.ABSENT;
                        case "unreadable" -> DurableKnowledgeState.CurrentStorageFailure.UNREADABLE;
                        case "wrong-size" -> DurableKnowledgeState.CurrentStorageFailure.WRONG_LENGTH;
                        case "aead" -> DurableKnowledgeState.CurrentStorageFailure.AEAD;
                        case "padding" -> DurableKnowledgeState.CurrentStorageFailure.PADDING;
                        case "object-id" -> DurableKnowledgeState.CurrentStorageFailure.OBJECT_ID;
                        default -> throw new AssertionError("Unknown unavailable reason");
                    } : DurableKnowledgeState.CurrentStorageFailure.ABSENT;
                    state = state.currentStorageFailure(symbolId(step.field("id").string()), failure);
                    assertEquals(before, state.records());
                    assertEquals(continuity, state.continuity());
                }
                case "local-security-corruption" -> state = state.localSecurityMemoryCorruption();
                case "query" -> {
                    Map<ObjectId, DurableRecord> before = state.records();
                    assertEquals(step.field("expect").field("integrity_failure").bool(),
                            state.continuity() == LOCAL_CONTINUITY_UNKNOWN, c.context());
                    assertEquals(before, state.records());
                    // All other query fields depend on graph/current-value/readiness semantics.
                }
                case "state-query" -> {
                    var expected = step.field("state_expect");
                    assertEquals(expected.field("known").array().stream().map(n -> symbolId(n.string())).collect(Collectors.toSet()),
                            state.records().keySet(), c.context());
                    assertEquals(expected.field("continuity_unknown").bool(), state.continuity() == LOCAL_CONTINUITY_UNKNOWN);
                    if (!step.field("id").string().isEmpty()) {
                        var record = state.record(symbolId(step.field("id").string()));
                        var parents = record instanceof KnownTokenNode t ? t.parents() : ((KnownDeviceNode) record).parents();
                        assertEquals(expected.field("parents").array().stream().map(n -> symbolId(n.string())).toList(), parents);
                    }
                    // device_heads and authoritative are explicitly deferred.
                }
                case "reclassify" -> { return; } // Stop: all dependent later queries are deferred too.
                default -> fail("Unexpected action in selected partial contract: " + step.field("action").string());
            }
        }
    }

    /** Symbolic authenticated-record invariant seam, NOT synthetic authenticated observations. */
    static DurableRecord symbolicRecord(Node n) {
        var id = symbolId(n.field("id").string());
        if (n.field("class").string().equals("OPAQUE_UNSCOPED")) {
            // This symbolic fixture has no encrypted bytes. Exact authentication/byte retention
            // is separately executed using opaque-retention's real envelope reference below.
            byte[] symbolicBytes = new byte[1024];
            byte[] label = CryptoSupport.ascii(n.field("semantic_digest").string());
            System.arraycopy(label, 0, symbolicBytes, 0, label.length);
            return new OpaqueUnscopedRecord(id, new SecurityBytes(symbolicBytes, 1024));
        }
        var identity = new SecurityBytes(symbolId(n.field("identity").string()).bytes(), 32);
        var parents = n.field("parents").isNull() ? List.<ObjectId>of()
                : n.field("parents").array().stream().map(p -> symbolId(p.string())).toList();
        var status = SemanticStatus.valueOf(n.field("class").string());
        int version = n.field("version").integer().intValueExact();
        var time = n.field("author_time").integer();
        // Portable graph fixtures omit author/key; fixed placeholders are only test inputs
        // to the consistency seam, never claimed to have passed the byte parser.
        return n.field("type").string().equals("TOKEN")
                ? new KnownTokenNode(id, version, status, identity, parents, new SecurityBytes(new byte[32], 32), time)
                : new KnownDeviceNode(id, version, status, identity, parents, time,
                        status == SemanticStatus.SUPPORTED_VALID ? new SecurityBytes(new byte[65], 65) : null);
    }

    static ObjectId symbolId(String name) {
        // Padded ASCII preserves symbolic ordering without inventing cryptographic collisions.
        return new ObjectId(Arrays.copyOf(CryptoSupport.ascii(name), 32));
    }

    private static void retention(Case c) throws Exception {
        var contract = c.data().field("retention");
        var fixture = DurableKnowledgeTest.fixture(contract.field("fixture_case").string());
        for (var trial : contract.field("trials").array()) {
            var crypto = fixture.data().field("crypto");
            byte[] synchronizedBytes = crypto.field("object_hex").hex();
            byte[] expectedBytes = synchronizedBytes.clone();
            var opened = EnvelopeReader.open(crypto.field("object_id").string(), synchronizedBytes, ProvenanceTest.root(fixture));
            assertEquals(EnvelopeReader.Status.AUTHENTICATED_OPAQUE_UNSCOPED, opened.status());
            var observation = AuthenticatedObservation.opaque(opened).orElseThrow();
            var update = DurableKnowledgeState.establishedEmpty().afterPersistence(observation, trial.field("persist").bool() ? COMMITTED : FAILED);
            var state = update.state();
            Arrays.fill(synchronizedBytes, (byte) 99); // hostile replacement
            state = state.currentStorageFailure(observation.record().objectId(), DurableKnowledgeState.CurrentStorageFailure.AEAD);
            state = state.currentStorageFailure(observation.record().objectId(), DurableKnowledgeState.CurrentStorageFailure.ABSENT);
            var retained = state.record(observation.record().objectId());
            var expected = trial.field("expect");
            assertEquals(expected.field("retained_exact").bool(), retained != null);
            assertEquals(expected.field("persistence_blocked").bool(), state.knowledgePersistenceBlocked());
            assertEquals(expected.field("class").string(), retained == null ? "" : "OPAQUE_UNSCOPED");
            if (retained != null) { assertArrayEquals(expectedBytes, ((OpaqueUnscopedRecord) retained).exactObjectBytes().bytes()); }
            else { assertEquals(DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED, update.outcome()); }
            assertEquals(LOCAL_CONTINUITY_KNOWN, state.continuity());
            // authoritative is deferred; this runner implements no readiness predicate.
        }
    }
}
