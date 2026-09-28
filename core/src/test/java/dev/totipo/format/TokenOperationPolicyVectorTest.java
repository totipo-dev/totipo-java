package dev.totipo.format;

import static dev.totipo.format.KnowledgeVectorTest.symbolId;
import static dev.totipo.format.TokenOperationPolicy.*;
import static dev.totipo.format.CandidateWarning.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/** Graph contract author=true is fully-confirmed feasibility, not publication permission. */
class TokenOperationPolicyVectorTest {
    /** Symbolic predecessor IDs are materialized; only the new child uses the real local writer. */
    @TestFactory
    List<DynamicTest> ordinaryUpdatePublication() throws Exception {
        var selected = Set.of("v1.graph.sequential.001", "v1.graph.equal-concurrent.001",
                "v1.graph.conflicting-concurrent.001", "v1.graph.missing-current-value.001",
                "v1.timestamp.equal-value-different-times.001", "v1.timestamp.fold-common-time.001",
                "v1.candidate.opaque-current.001");
        var all = new ArrayList<>(VectorCaseLoader.graphCases());
        all.addAll(VectorCaseLoader.timestampCases()); all.addAll(VectorCaseLoader.candidateCases());
        var cases = all.stream().filter(c -> selected.contains(c.id())).toList();
        assertEquals(selected, cases.stream().map(Case::id).collect(Collectors.toSet()));
        return cases.stream().map(c -> DynamicTest.dynamicTest(c.id() + " [M3.2b PARTIAL writer extension]", () -> {
            var steps = c.data().field("graph").field("steps").array();
            var adapter = new CurrentTokenValueVectorTest.AuthenticatedSymbols(steps);
            try (var h = new InitialDeviceAdvertisementTest.Harness()) {
                var available = new HashMap<ObjectId, ReadableTokenValue>();
                for (var step : steps) {
                    switch (step.field("action").string()) {
                        case "learn" -> {
                            var material = adapter.materialize(step.field("node").field("id").string());
                            h.session.commit(material.observation());
                            if (material.readable() != null) available.put(material.id(), material.readable());
                        }
                        case "disappear" -> available.remove(adapter.materialize(step.field("id").string()).id());
                        case "query" -> {
                            var token = new SecurityBytes(symbolId(step.field("query").field("identity").string()).bytes(), 32);
                            java.util.function.Supplier<TokenUpdatePublication.Context> context = () -> {
                                var g = new GraphTopology(h.session.knowledge());
                                return new TokenUpdatePublication.Context(h.context(), g, new CurrentReadableValues(g, available.values()));
                            };
                            var snapshot = context.get();
                            var view = CurrentTokenValueEvaluator.evaluate(snapshot.graph(), token, snapshot.readable());
                            assertEquals(adapter.ids(step.field("expect").field("heads")), view.currentHeadIds());
                            var desired = view.distinctReadableValues().isEmpty() ? InitialTokenPublicationTest.value()
                                    : view.distinctReadableValues().iterator().next();
                            int appends = h.memory.appends;
                            var result = TokenUpdatePublication.publish(h.root, context, h.identity, token, desired,
                                    new byte[8], TokenUpdatePublication.Intent.ORDINARY, h.store, List.of());
                            var expected = switch (view.state()) {
                                case SEMANTICALLY_UNAMBIGUOUS -> InitialTokenPublication.Status.PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED;
                                case WHOLE_STATE_CONFLICT -> InitialTokenPublication.Status.CONFIRMATION_REQUIRED_CONFLICT;
                                case VALUE_INCOMPLETE_UNAVAILABLE -> InitialTokenPublication.Status.CONFIRMATION_REQUIRED_UNAVAILABLE;
                                case VALUE_INCOMPLETE_OPAQUE -> InitialTokenPublication.Status.CURRENT_OPAQUE_BLOCKED;
                                default -> throw new AssertionError("Unexpected vector state");
                            };
                            assertEquals(expected, result.status());
                            if (result.receipt() == null) {
                                assertEquals(0, h.keys.signs); assertEquals(0, h.store.calls); assertEquals(appends, h.memory.appends);
                            } else {
                                assertEquals(1, h.keys.signs);
                                var node = (KnownTokenNode) h.session.knowledge().record(result.receipt().objectId());
                                assertEquals(DeviceWriter.canonicalParents(view.currentHeadIds()), node.parents());
                                assertEquals(Set.of(node.objectId()), new GraphTopology(h.session.knowledge()).currentTokenHeads(token));
                                var parsed = EnvelopeReader.open(node.objectId().filename(), h.store.get(node.objectId()), h.root).plaintext();
                                assertEquals(desired, TokenValue.from(parsed.token()));
                            }
                        }
                        default -> fail("Unhandled selected vector action");
                    }
                }
            }
        })).toList();
    }

    @TestFactory
    List<DynamicTest> exactUnscopedRetentionReadiness() throws Exception {
        var c = VectorCaseLoader.futureCases().stream()
                .filter(v -> v.id().equals("v1.future.unscoped-retains-exact-object.001")).findFirst().orElseThrow();
        var contract = c.data().field("retention");
        var fixture = DurableKnowledgeTest.fixture(contract.field("fixture_case").string());
        var tests = new ArrayList<DynamicTest>();
        for (var trial : contract.field("trials").array()) {
            tests.add(DynamicTest.dynamicTest(c.id() + " persist=" + trial.field("persist").bool(), () -> {
                var crypto = fixture.data().field("crypto");
                var observation = AuthenticatedObservation.opaque(EnvelopeReader.open(
                        crypto.field("object_id").string(), crypto.field("object_hex").hex(),
                        ProvenanceTest.root(fixture))).orElseThrow();
                var a = TokenValueFixtures.readable(1, TokenValueFixtures.value());
                var s = GraphTopologyTest.state(a.routing()).afterPersistence(observation,
                        trial.field("persist").bool() ? DurableKnowledgeState.PersistenceResult.COMMITTED
                                : DurableKnowledgeState.PersistenceResult.FAILED).state();
                s = s.currentStorageFailure(observation.record().objectId(), DurableKnowledgeState.CurrentStorageFailure.ABSENT);
                var r = new VaultReadiness(s, DiscoveryState.READY);
                assertEquals(trial.field("expect").field("authoritative").bool(), r.authoritativeVaultReady());
                assertEquals(trial.field("expect").field("persistence_blocked").bool(), s.knowledgePersistenceBlocked());
                assertEquals(trial.field("persist").bool(), r.baseOperationSafe());
                assertEquals(trial.field("persist").bool(), r.candidateUseReady());
                var p = TokenOperationPolicyTest.policy(s, a);
                assertFalse(p.ordinaryUse().eligible());
                assertEquals(AuthorshipStage.BLOCKED, p.authorship().stage());
                assertEquals(trial.field("persist").bool(), p.candidateUse(TokenOperationPolicyTest.pin(a)).eligible());
                System.out.println(c.id() + " partial readiness PASS; ordinary/candidate/authorship tested with added LIVE evidence;"
                        + " actual persistence and compatible reprocessing DEFERRED");
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> provenanceDoesNotGateCandidateUse() throws Exception {
        return VectorCaseLoader.provenanceCases().stream()
                .filter(c -> c.data().field("operation").string().equals("provenance"))
                .map(c -> DynamicTest.dynamicTest(c.id() + " [candidate provenance independence]", () -> {
                    var semantic = TlvTestBytes.replace(ProvenanceTest.token().semanticBytes(), 0xff01,
                            c.data().field("input").field("signature").base64());
                    var assertion = ProvenanceTest.valid(semantic, ProvenanceTest.root(c));
                    var status = c.data().has("public_key_hex")
                            ? ProvenanceTest.evaluate(assertion, ProvenanceTest.root(c), c.data().field("public_key_hex").hex())
                            : ProvenanceTest.evaluate(assertion, ProvenanceTest.root(c));
                    assertEquals(c.expected(), status.name());
                    var a = ReadableTokenValue.supported(assertion);
                    var p = TokenOperationPolicyTest.policy(GraphTopologyTest.state(a.routing()), DiscoveryState.READY,
                            a.tokenId(), a);
                    assertTrue(p.candidateUse(TokenOperationPolicyTest.pin(a)).eligible());
                    assertTrue(p.ordinaryUse().eligible());
                    assertEquals(AuthorshipStage.CAN_PROCEED_TO_PLAN, p.authorship().stage());
                    // No status/key is supplied to policy; publication provenance is deferred.
                })).toList();
    }

    private static final Set<String> SELECTED = Set.of(
            "v1.graph.sequential.001", "v1.graph.equal-concurrent.001",
            "v1.graph.conflicting-concurrent.001", "v1.graph.missing-current-value.001",
            "v1.graph.late-parent.001", "v1.graph.intermediate-disappears.001",
            "v1.graph.known-id-corrupt-bytes-retain-node.001", "v1.graph.local-security-memory-corruption.001",
            "v1.graph.reappearance.001", "v1.graph.wrong-identity-parent.001",
            "v1.future.concurrent-supported-opaque.001", "v1.future.supported-descendant.001",
            "v1.future.version-does-not-order.001", "v1.future.unrelated-token.001",
            "v1.future.disappearance-retains-routing.001", "v1.future.scoped-token.001",
            "v1.future.device-presentation.001", "v1.future.unscoped-authoritative-block.001",
            "v1.future.unscoped-candidate-use.001", "v1.future.unscoped-sticky.001",
            "v1.timestamp.equal-value-different-times.001", "v1.timestamp.fold-common-time.001",
            "v1.candidate.conflict-a.001", "v1.candidate.continuity-block.001",
            "v1.candidate.current-peer-missing.001", "v1.candidate.discovery-incomplete.001",
            "v1.candidate.historical-current-missing.001", "v1.candidate.opaque-current.001",
            "v1.candidate.persistence-block.001");

    @TestFactory
    List<DynamicTest> partialOperationContracts() throws Exception {
        var all = new ArrayList<>(VectorCaseLoader.graphCases());
        all.addAll(VectorCaseLoader.futureCases());
        all.addAll(VectorCaseLoader.timestampCases());
        all.addAll(VectorCaseLoader.candidateCases());
        var selected = all.stream().filter(c -> SELECTED.contains(c.id())).toList();
        assertEquals(SELECTED, selected.stream().map(Case::id).collect(Collectors.toSet()));
        assertTrue(SELECTED.containsAll(VectorCaseLoader.candidateCases().stream().map(Case::id).toList()));
        return selected.stream().map(c -> DynamicTest.dynamicTest(c.id() + " [M2.3 PARTIAL]", () -> execute(c))).toList();
    }

    private static void execute(Case c) throws Exception {
        var steps = c.data().field("graph").field("steps").array();
        var tokens = new CurrentTokenValueVectorTest.AuthenticatedSymbols(steps);
        // Only non-TOKEN symbolic knowledge uses the existing trusted record seam.
        // Every candidate value uses real M1 authentication/assertion validation.
        var nonTokens = new HashMap<String, DurableRecord>();
        for (var step : steps) {
            if (step.field("action").string().equals("learn")
                    && !step.field("node").field("type").string().equals("TOKEN")) {
                nonTokens.put(step.field("node").field("id").string(), KnowledgeVectorTest.symbolicRecord(step.field("node")));
            }
        }
        var s = DurableKnowledgeState.establishedEmpty();
        var discovery = DiscoveryState.READY; // Portable contract starts established/complete.
        var available = new HashMap<ObjectId, ReadableTokenValue>();
        var trace = new ArrayList<String>();
        for (var step : steps) {
            switch (step.field("action").string()) {
                case "learn", "persist-fails" -> {
                    var symbol = step.field("node").field("id").string();
                    var outcome = step.field("action").string().equals("learn")
                            ? DurableKnowledgeState.PersistenceResult.COMMITTED : DurableKnowledgeState.PersistenceResult.FAILED;
                    if (nonTokens.containsKey(symbol)) {
                        s = s.afterRecordPersistence(nonTokens.get(symbol), outcome).state();
                    } else {
                        var material = tokens.materialize(symbol);
                        s = s.afterPersistence(material.observation(), outcome).state();
                        if (outcome == DurableKnowledgeState.PersistenceResult.COMMITTED && material.readable() != null) {
                            available.put(material.id(), material.readable());
                        }
                    }
                }
                case "discovery-incomplete" -> discovery = step.has("flag") && step.field("flag").bool()
                        ? DiscoveryState.PROCESSING_INCOMPLETE : DiscoveryState.READY;
                case "continuity-unknown" -> {
                    assertTrue(step.field("flag").bool(), "M2.3 cannot reset continuity");
                    s = s.localSecurityMemoryCorruption();
                }
                case "local-security-corruption" -> s = s.localSecurityMemoryCorruption();
                case "disappear", "remote-unavailable" -> {
                    var symbol = step.field("id").string();
                    var id = nonTokens.containsKey(symbol) ? nonTokens.get(symbol).objectId() : tokens.materialize(symbol).id();
                    var before = s.records();
                    var failure = !step.has("reason") ? DurableKnowledgeState.CurrentStorageFailure.ABSENT
                            : switch (step.field("reason").string()) {
                                case "absent" -> DurableKnowledgeState.CurrentStorageFailure.ABSENT;
                                case "unreadable" -> DurableKnowledgeState.CurrentStorageFailure.UNREADABLE;
                                case "wrong-size" -> DurableKnowledgeState.CurrentStorageFailure.WRONG_LENGTH;
                                case "aead" -> DurableKnowledgeState.CurrentStorageFailure.AEAD;
                                case "padding" -> DurableKnowledgeState.CurrentStorageFailure.PADDING;
                                case "object-id" -> DurableKnowledgeState.CurrentStorageFailure.OBJECT_ID;
                                default -> throw new AssertionError("Unknown unavailable reason");
                            };
                    s = s.currentStorageFailure(id, failure);
                    if (!step.has("flag") || !step.field("flag").bool()) { available.remove(id); }
                    assertEquals(before, s.records());
                }
                case "state-query" -> {
                    var expected = step.field("state_expect");
                    var r = new VaultReadiness(s, discovery);
                    assertEquals(expected.field("authoritative").bool(), r.authoritativeVaultReady());
                    assertEquals(expected.field("continuity_unknown").bool(),
                            s.continuity() == LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN);
                }
                case "query" -> {
                    var before = s.records();
                    var r = new VaultReadiness(s, discovery);
                    var g = new GraphTopology(s);
                    var t = new SecurityBytes(symbolId(step.field("query").field("identity").string()).bytes(), 32);
                    var p = new TokenOperationPolicy(r, g, t, new CurrentReadableValues(g, available.values()));
                    var expected = step.field("expect");
                    assertEquals(expected.field("integrity_failure").bool(),
                            s.continuity() == LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN);
                    assertEquals(tokens.ids(expected.field("heads")), p.current().currentHeadIds());
                    String state = switch (p.current().state()) {
                        case NO_KNOWN_CURRENT_STATE -> "EMPTY";
                        case SEMANTICALLY_UNAMBIGUOUS -> "UNAMBIGUOUS";
                        case WHOLE_STATE_CONFLICT -> "CONFLICT";
                        default -> p.current().state().name();
                    };
                    assertEquals(expected.field("value_state").string(), state);
                    assertEquals(expected.field("ordinary").bool(), p.ordinaryUse().eligible(), c.context());
                    assertEquals(expected.field("author").bool(), p.authorship().stage() != AuthorshipStage.BLOCKED);
                    if (r.authoritativeVaultReady()) {
                        if (state.equals("CONFLICT") || state.equals("VALUE_INCOMPLETE_UNAVAILABLE")) {
                            assertEquals(AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW, p.authorship().stage());
                        }
                    }
                    String symbol = step.field("query").field("candidate").string();
                    CandidateUse use = null;
                    if (!symbol.isEmpty() && !nonTokens.containsKey(symbol)) {
                        var material = tokens.materialize(symbol);
                        if (material.readable() != null && material.readable().value().status() == 1) {
                            var pin = TokenOperationPolicyTest.pin(material.readable());
                            use = p.candidateUse(pin);
                            assertEquals(pin, use.selected());
                            if (use.eligible()) {
                                assertEquals(p.current().currentHeadIds().contains(pin.objectId()),
                                        use.warnings().contains(CANDIDATE_CURRENT));
                                assertEquals(!p.current().currentHeadIds().contains(pin.objectId()),
                                        use.warnings().contains(CANDIDATE_HISTORICAL));
                                assertEquals(discovery == DiscoveryState.PROCESSING_INCOMPLETE,
                                        use.warnings().contains(DISCOVERY_INCOMPLETE));
                                assertEquals(r.activeOpaqueUnscoped(), use.warnings().contains(OPAQUE_UNSCOPED_ACTIVE));
                                assertEquals(!p.current().opaqueHeadIds().isEmpty(), use.warnings().contains(CURRENT_OPAQUE_PRESENT));
                                assertEquals(!p.current().unavailableSupportedHeadIds().isEmpty(),
                                        use.warnings().contains(CURRENT_UNAVAILABLE_PRESENT));
                                assertEquals(p.current().distinctReadableValues().size() > 1,
                                        use.warnings().contains(CURRENT_CONFLICT));
                            }
                        }
                    }
                    boolean eligible = use != null && use.eligible();
                    assertEquals(expected.field("candidate").bool(), eligible);
                    // Contract means a warning accompanying permitted explicit use, not
                    // the absence of descriptive facts when base safety blocks the operation.
                    assertEquals(expected.field("candidate_warning").bool(), eligible
                            && use.warnings().contains(NOT_ATTESTED_UNIQUELY_CURRENT));
                    assertEquals(before, s.records());
                    trace.add("B/A/C=" + r.baseOperationSafe() + "/" + r.authoritativeVaultReady() + "/"
                            + r.candidateUseReady() + " ordinary=" + p.ordinaryUse().reason() + " candidate=" + eligible
                            + " author=" + p.authorship().stage() + "/" + p.authorship().reason());
                }
                case "reclassify" -> {
                    System.out.println(c.id() + " M2.3 PARTIAL " + trace
                            + "; compatible reclassification and dependent queries DEFERRED");
                    return;
                }
                default -> fail("Unhandled selected contract action: " + step.field("action").string());
            }
        }
        System.out.println(c.id() + " M2.3 PARTIAL " + trace
                + "; actual writer/confirmation/freshness/discovery/persistence/presentation DEFERRED");
    }
}
