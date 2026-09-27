package dev.totipo.format;

import static dev.totipo.format.TokenValueFixtures.*;
import static dev.totipo.format.GraphTopologyTest.*;
import static dev.totipo.format.TokenOperationPolicy.*;
import static dev.totipo.format.CandidateWarning.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class TokenOperationPolicyTest {
    static OpaqueUnscopedRecord unscoped() {
        return new OpaqueUnscopedRecord(id(900), new SecurityBytes(new byte[1024], 1024));
    }
    static DurableKnowledgeState blocked(DurableKnowledgeState s) {
        return s.afterRecordPersistence(node(true, 901, 100, 1),
                DurableKnowledgeState.PersistenceResult.FAILED).state();
    }
    static TokenOperationPolicy policy(DurableKnowledgeState s, DiscoveryState d, SecurityBytes t,
                                        ReadableTokenValue... evidence) {
        var g = new GraphTopology(s);
        return new TokenOperationPolicy(new VaultReadiness(s, d), g, t,
                new CurrentReadableValues(g, List.of(evidence)));
    }
    static TokenOperationPolicy policy(DurableKnowledgeState s, ReadableTokenValue... evidence) {
        return policy(s, DiscoveryState.READY, TOKEN, evidence);
    }
    static CandidateToken pin(ReadableTokenValue v) { return new CandidateToken(v.objectId(), v.tokenId(), v.value()); }

    @TestFactory
    List<DynamicTest> exhaustiveSafetyAndOperationMatrix() throws Exception {
        var a = readable(1, value());
        var tests = new ArrayList<DynamicTest>();
        for (boolean unknown : List.of(false, true)) {
            for (boolean persistence : List.of(false, true)) {
                for (var discovery : DiscoveryState.values()) {
                    for (boolean opaque : List.of(false, true)) {
                        tests.add(DynamicTest.dynamicTest(unknown + "/" + persistence + "/" + discovery + "/" + opaque, () -> {
                            var s = state(a.routing());
                            if (opaque) { s = learn(s, unscoped()); }
                            if (unknown) { s = s.localSecurityMemoryCorruption(); }
                            if (persistence) { s = blocked(s); }
                            var r = new VaultReadiness(s, discovery);
                            boolean base = !unknown && !persistence;
                            boolean authoritative = base && discovery == DiscoveryState.READY && !opaque;
                            assertEquals(base, r.baseOperationSafe());
                            assertEquals(base, r.candidateUseReady());
                            assertEquals(authoritative, r.authoritativeVaultReady());
                            var p = policy(s, discovery, TOKEN, a);
                            assertEquals(authoritative, p.ordinaryUse().eligible());
                            assertEquals(base, p.candidateUse(pin(a)).eligible());
                            assertEquals(authoritative, p.authorship().stage() == AuthorshipStage.CAN_PROCEED_TO_PLAN);
                            var reason = !base ? Reason.BASE_OPERATION_UNSAFE
                                    : discovery != DiscoveryState.READY ? Reason.DISCOVERY_INCOMPLETE
                                    : opaque ? Reason.OPAQUE_UNSCOPED_ACTIVE : Reason.ELIGIBLE;
                            assertEquals(reason, p.ordinaryUse().reason());
                            assertEquals(reason, p.authorship().reason());
                        }));
                    }
                }
            }
        }
        return tests;
    }

    @Test
    void equalHeadsHaveOneOrdinaryValueButTwoExactCandidates() throws Exception {
        var a = readable(1, value()); var b = readable(2, value());
        var p = policy(state(a.routing(), b.routing()), a, b);
        assertEquals(value(), p.ordinaryUse().value().orElseThrow());
        assertEquals(2, p.current().currentHeadIds().size());
        assertEquals(2, p.candidates().size());
        for (var c : p.candidates().values()) {
            var result = p.candidateUse(c);
            assertTrue(result.eligible());
            assertEquals(c, result.selected());
            assertEquals(Set.of(NOT_ATTESTED_UNIQUELY_CURRENT, CANDIDATE_CURRENT), result.warnings());
        }
        assertEquals(p.current().currentHeadIds(), p.authorship().currentHeads());
    }

    @TestFactory
    List<DynamicTest> ordinaryAndAuthorshipValueStates() throws Exception {
        var a = readable(1, value());
        var b = readable(2, value(1, "other", "account", 1, 6, 30, (byte) 12));
        var dead = readable(3, value(2, "Example", "alice", 1, 6, 30, (byte) 42));
        var opaque = opaque(4);
        record Trial(String name, DurableKnowledgeState state, List<ReadableTokenValue> evidence,
                     Reason ordinary, AuthorshipStage author, Reason authorReason) {}
        return List.of(
                new Trial("empty", state(), List.of(), Reason.NO_CURRENT_STATE,
                        AuthorshipStage.CAN_PROCEED_TO_PLAN, Reason.NO_CURRENT_STATE),
                new Trial("live", state(a.routing()), List.of(a), Reason.ELIGIBLE,
                        AuthorshipStage.CAN_PROCEED_TO_PLAN, Reason.ELIGIBLE),
                new Trial("tombstone", state(dead.routing()), List.of(dead), Reason.CURRENT_TOMBSTONE,
                        AuthorshipStage.CAN_PROCEED_TO_PLAN, Reason.RESTORATION_INTENT_DEFERRED),
                new Trial("live/dead", state(a.routing(), dead.routing()), List.of(a, dead), Reason.CURRENT_CONFLICT,
                        AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW, Reason.CURRENT_CONFLICT),
                new Trial("conflict", state(a.routing(), b.routing()), List.of(a, b), Reason.CURRENT_CONFLICT,
                        AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW, Reason.CURRENT_CONFLICT),
                new Trial("unavailable", state(a.routing(), b.routing()), List.of(a), Reason.CURRENT_UNAVAILABLE,
                        AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW, Reason.CURRENT_UNAVAILABLE),
                new Trial("opaque", state(a.routing(), opaque), List.of(a), Reason.CURRENT_OPAQUE,
                        AuthorshipStage.BLOCKED, Reason.CURRENT_OPAQUE)
        ).stream().map(t -> DynamicTest.dynamicTest(t.name(), () -> {
            var p = policy(t.state(), t.evidence().toArray(ReadableTokenValue[]::new));
            assertEquals(t.ordinary(), p.ordinaryUse().reason());
            assertEquals(t.ordinary() == Reason.ELIGIBLE, p.ordinaryUse().value().isPresent());
            assertEquals(t.author(), p.authorship().stage());
            assertEquals(t.authorReason(), p.authorship().reason());
            for (var v : t.evidence()) {
                if (v.value().status() == 1) { assertTrue(p.candidateUse(pin(v)).eligible()); }
                else { assertFalse(p.candidates().containsKey(v.objectId())); }
            }
        })).toList();
    }

    @Test
    void historicalCandidatesRemainExplicitAndAvailabilityIsFresh() throws Exception {
        var a = readable(1, value()); var b = readable(2, value(), a.objectId());
        var s = state(a.routing(), b.routing());
        var complete = policy(s, a, b);
        assertTrue(complete.ordinaryUse().eligible());
        assertEquals(Set.of(b.objectId()), complete.current().currentHeadIds());
        assertEquals(Set.of(NOT_ATTESTED_UNIQUELY_CURRENT, CANDIDATE_HISTORICAL),
                complete.candidateUse(pin(a)).warnings());
        assertTrue(complete.candidateUse(pin(b)).warnings().contains(CANDIDATE_CURRENT));
        var missing = policy(s, a);
        assertEquals(Reason.CURRENT_UNAVAILABLE, missing.ordinaryUse().reason());
        assertTrue(missing.candidateUse(pin(a)).eligible());
        assertEquals(Set.of(NOT_ATTESTED_UNIQUELY_CURRENT, CANDIDATE_HISTORICAL, CURRENT_UNAVAILABLE_PRESENT),
                missing.candidateUse(pin(a)).warnings());
        assertEquals(Reason.CANDIDATE_NOT_AVAILABLE, missing.candidateUse(pin(b)).reason());
        assertTrue(policy(s).candidates().isEmpty());
    }

    @Test
    void combinedWarningsDoNotBlockAndQueriesDoNotMutate() throws Exception {
        var a = readable(1, value()); var o = opaque(2, a.objectId());
        var b = readable(3, value());
        var c = readable(4, value(1, "different", "account", 1, 6, 30, (byte) 33));
        var missing = readable(5, value());
        var s = state(a.routing(), o, b.routing(), c.routing(), missing.routing(), unscoped());
        var records = s.records(); var g = new GraphTopology(s);
        var evidence = new CurrentReadableValues(g, List.of(a, b, c));
        var r = new VaultReadiness(s, DiscoveryState.PROCESSING_INCOMPLETE);
        var p = new TokenOperationPolicy(r, g, TOKEN, evidence);
        var view = p.current();
        var expected = Set.of(NOT_ATTESTED_UNIQUELY_CURRENT, CANDIDATE_HISTORICAL, DISCOVERY_INCOMPLETE,
                OPAQUE_UNSCOPED_ACTIVE, CURRENT_OPAQUE_PRESENT, CURRENT_UNAVAILABLE_PRESENT, CURRENT_CONFLICT);
        for (int i = 0; i < 3; i++) {
            var result = p.candidateUse(pin(a));
            assertTrue(result.eligible()); assertEquals(expected, result.warnings());
            assertEquals(Reason.DISCOVERY_INCOMPLETE, p.ordinaryUse().reason());
            assertEquals(AuthorshipStage.BLOCKED, p.authorship().stage());
            assertEquals(records, s.records()); assertEquals(view, p.current());
            assertEquals(view, CurrentTokenValueEvaluator.evaluate(g, TOKEN, evidence));
        }
        assertThrows(UnsupportedOperationException.class, () -> p.candidates().clear());
        assertThrows(UnsupportedOperationException.class, () -> p.candidateUse(pin(a)).warnings().clear());
        assertFalse(p.candidateUse(pin(a)).toString().contains("Example"));
        assertFalse(p.ordinaryUse().toString().contains("alice"));
    }

    @Test
    void catalogRejectsWrongTokenUnavailableOpaqueTombstoneAndForgedPin() throws Exception {
        var a = readable(1, value()); var other = readable(2, identity(101), value());
        var dead = readable(3, value(2, "Example", "alice", 1, 6, 30, (byte) 42));
        var missing = readable(4, value()); var o = opaque(5);
        var p = policy(state(a.routing(), other.routing(), dead.routing(), missing.routing(), o), a, other, dead);
        assertEquals(Set.of(a.objectId()), p.candidates().keySet());
        assertFalse(p.candidateUse(pin(other)).eligible());
        assertFalse(p.candidateUse(pin(missing)).eligible());
        assertFalse(p.candidateUse(new CandidateToken(o.objectId(), TOKEN, value())).eligible());
        assertFalse(p.candidateUse(new CandidateToken(a.objectId(), TOKEN,
                value(1, "forged", "account", 1, 6, 30, (byte) 1))).eligible());
        assertThrows(IllegalArgumentException.class, () -> pin(dead));
        // Fixtures have empty (unresolved) signatures; candidate authority never invokes provenance.
        assertTrue(p.candidateUse(pin(a)).eligible());
    }

    @Test
    void scopedOpaqueAndDeviceDoNotDegradeOtherTokenButGlobalGatesDo() throws Exception {
        var a = readable(1, value()); var b = readable(2, identity(101), value());
        var o = opaque(3);
        var s = state(a.routing(), b.routing(), o, node(false, 77, 55, 2));
        assertTrue(new VaultReadiness(s, DiscoveryState.READY).authoritativeVaultReady());
        assertEquals(Reason.CURRENT_OPAQUE, policy(s, a, b).ordinaryUse().reason());
        assertTrue(policy(s, DiscoveryState.READY, b.tokenId(), a, b).ordinaryUse().eligible());
        assertEquals(AuthorshipStage.CAN_PROCEED_TO_PLAN,
                policy(s, DiscoveryState.READY, b.tokenId(), a, b).authorship().stage());
        for (var t : List.of(TOKEN, b.tokenId())) {
            for (var d : DiscoveryState.values()) {
                var global = d == DiscoveryState.READY ? learn(s, unscoped()) : s;
                var p = policy(global, d, t, a, b);
                assertFalse(p.ordinaryUse().eligible());
                assertEquals(AuthorshipStage.BLOCKED, p.authorship().stage());
                assertTrue(p.candidateUse(pin(t.equals(TOKEN) ? a : b)).eligible());
            }
        }
    }

    @Test
    void snapshotMismatchAndCyclesFailClosedAndCurrentSafetyOverridesOldDescription() throws Exception {
        var a = readable(1, value()); var s = state(a.routing()); var g = new GraphTopology(s);
        var evidence = new CurrentReadableValues(g, List.of(a));
        assertThrows(IllegalStateException.class, () -> new TokenOperationPolicy(
                new VaultReadiness(learn(s, unscoped()), DiscoveryState.READY), g, TOKEN, evidence));
        assertThrows(IllegalStateException.class, () -> new TokenOperationPolicy(
                new VaultReadiness(s, DiscoveryState.READY), new GraphTopology(s), TOKEN, evidence));
        assertEquals(CurrentTokenValueState.SEMANTICALLY_UNAMBIGUOUS,
                CurrentTokenValueEvaluator.evaluate(g, TOKEN, evidence).state());
        var unsafe = new TokenOperationPolicy(new VaultReadiness(s.localSecurityMemoryCorruption(), DiscoveryState.READY),
                g, TOKEN, evidence);
        assertFalse(unsafe.ordinaryUse().eligible()); assertFalse(unsafe.candidateUse(pin(a)).eligible());
        var cycle = state(node(true, 1, 100, 1, 2), node(true, 2, 100, 1, 1));
        assertFalse(new VaultReadiness(cycle, DiscoveryState.READY).candidateUseReady());
        assertThrows(IllegalStateException.class, () -> policy(cycle));
        assertThrows(NullPointerException.class, () -> new VaultReadiness(s, null));
        assertThrows(NullPointerException.class, () -> new VaultReadiness(null, DiscoveryState.READY));
    }
}
