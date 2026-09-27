package dev.totipo.format;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Read-only §§33/35/38 policy over one supplied snapshot. Eligible now is not safe
 * forever: later orchestration must perform the immediate pre-operation recheck.
 * No OTP, persistence, discovery, confirmation, provenance or writer execution.
 * Operates only within an already-established vault continuity epoch; application
 * orchestration must satisfy the outer §10 establishment/binding prerequisite
 * documented by {@link VaultReadiness} before ordinary exposure or TOKEN authorship.
 */
final class TokenOperationPolicy {
    /** Diagnostics only, not serialized protocol state. */
    enum Reason {
        ELIGIBLE, BASE_OPERATION_UNSAFE, DISCOVERY_INCOMPLETE, OPAQUE_UNSCOPED_ACTIVE,
        NO_CURRENT_STATE, CURRENT_OPAQUE, CURRENT_UNAVAILABLE, CURRENT_CONFLICT,
        CURRENT_TOMBSTONE, CANDIDATE_NOT_AVAILABLE, RESTORATION_INTENT_DEFERRED
    }
    enum AuthorshipStage { BLOCKED, CAN_PROCEED_TO_PLAN, REQUIRES_CONFIRMATION_WORKFLOW }

    record OrdinaryUse(Reason reason, Optional<TokenValue> value) {
        OrdinaryUse {
            Objects.requireNonNull(reason);
            Objects.requireNonNull(value);
            if ((reason == Reason.ELIGIBLE) != value.isPresent()
                    || value.filter(v -> v.status() != 1).isPresent()) {
                throw new IllegalArgumentException("Invalid ordinary result");
            }
        }
        boolean eligible() { return reason == Reason.ELIGIBLE; }
    }
    record CandidateUse(Reason reason, CandidateToken selected, Set<CandidateWarning> warnings) {
        CandidateUse {
            Objects.requireNonNull(reason);
            Objects.requireNonNull(selected);
            warnings = Set.copyOf(warnings);
        }
        boolean eligible() { return reason == Reason.ELIGIBLE; }
    }
    /** Planning gate only. A tombstone defers LIVE restoration intent to the future plan. */
    record Authorship(AuthorshipStage stage, Reason reason, Set<ObjectId> currentHeads) {
        Authorship {
            Objects.requireNonNull(stage);
            Objects.requireNonNull(reason);
            currentHeads = Set.copyOf(currentHeads);
        }
    }

    private final VaultReadiness readiness;
    private final CurrentTokenValueView current;
    private final Map<ObjectId, CandidateToken> candidates;

    TokenOperationPolicy(VaultReadiness readiness, GraphTopology topology, SecurityBytes tokenId,
                         CurrentReadableValues readable) {
        this.readiness = Objects.requireNonNull(readiness);
        Objects.requireNonNull(tokenId);
        topology.requireKnowledge(readiness.knowledge());
        // Reuse M2.2's binding check and exact partitions; reject resolved cycles.
        current = CurrentTokenValueEvaluator.evaluate(topology, tokenId, readable);
        var catalog = new HashMap<ObjectId, CandidateToken>();
        for (var evidence : readable.evidence()) {
            if (evidence.tokenId().equals(tokenId) && evidence.value().status() == 1) {
                catalog.put(evidence.objectId(), new CandidateToken(evidence.objectId(), tokenId, evidence.value()));
            }
        }
        candidates = Map.copyOf(catalog);
    }

    CurrentTokenValueView current() { return current; }
    /** Exact assertions, including historical ones; equal values do not collapse IDs. */
    Map<ObjectId, CandidateToken> candidates() { return candidates; }

    /** Precedence: base safety, discovery, unscoped evidence, M2.2 state, tombstone. */
    private Reason authoritativeBlocker() {
        if (!readiness.baseOperationSafe()) { return Reason.BASE_OPERATION_UNSAFE; }
        if (readiness.discovery() != DiscoveryState.READY) { return Reason.DISCOVERY_INCOMPLETE; }
        if (readiness.activeOpaqueUnscoped()) { return Reason.OPAQUE_UNSCOPED_ACTIVE; }
        return Reason.ELIGIBLE;
    }

    OrdinaryUse ordinaryUse() {
        var reason = authoritativeBlocker();
        if (reason == Reason.ELIGIBLE) {
            reason = switch (current.state()) {
                case NO_KNOWN_CURRENT_STATE -> Reason.NO_CURRENT_STATE;
                case VALUE_INCOMPLETE_OPAQUE -> Reason.CURRENT_OPAQUE;
                case VALUE_INCOMPLETE_UNAVAILABLE -> Reason.CURRENT_UNAVAILABLE;
                case WHOLE_STATE_CONFLICT -> Reason.CURRENT_CONFLICT;
                case SEMANTICALLY_UNAMBIGUOUS -> uniqueValue().status() == 1
                        ? Reason.ELIGIBLE : Reason.CURRENT_TOMBSTONE;
            };
        }
        return new OrdinaryUse(reason, reason == Reason.ELIGIBLE ? Optional.of(uniqueValue()) : Optional.empty());
    }

    /** Explicit selection only; never called as an ordinary-use fallback. */
    CandidateUse candidateUse(CandidateToken selected) {
        Objects.requireNonNull(selected);
        if (!selected.equals(candidates.get(selected.objectId()))) {
            return new CandidateUse(Reason.CANDIDATE_NOT_AVAILABLE, selected, Set.of());
        }
        var facts = EnumSet.of(CandidateWarning.NOT_ATTESTED_UNIQUELY_CURRENT);
        facts.add(current.currentHeadIds().contains(selected.objectId())
                ? CandidateWarning.CANDIDATE_CURRENT : CandidateWarning.CANDIDATE_HISTORICAL);
        if (readiness.discovery() == DiscoveryState.PROCESSING_INCOMPLETE) {
            facts.add(CandidateWarning.DISCOVERY_INCOMPLETE);
        }
        if (readiness.activeOpaqueUnscoped()) { facts.add(CandidateWarning.OPAQUE_UNSCOPED_ACTIVE); }
        if (!current.opaqueHeadIds().isEmpty()) { facts.add(CandidateWarning.CURRENT_OPAQUE_PRESENT); }
        if (!current.unavailableSupportedHeadIds().isEmpty()) {
            facts.add(CandidateWarning.CURRENT_UNAVAILABLE_PRESENT);
        }
        // Known readable disagreement is worth disclosing even under incomplete state.
        if (current.distinctReadableValues().size() > 1) { facts.add(CandidateWarning.CURRENT_CONFLICT); }
        return new CandidateUse(readiness.candidateUseReady() ? Reason.ELIGIBLE : Reason.BASE_OPERATION_UNSAFE,
                selected, facts);
    }

    Authorship authorship() {
        var reason = authoritativeBlocker();
        if (reason != Reason.ELIGIBLE) { return authorship(AuthorshipStage.BLOCKED, reason); }
        return switch (current.state()) {
            case VALUE_INCOMPLETE_OPAQUE -> authorship(AuthorshipStage.BLOCKED, Reason.CURRENT_OPAQUE);
            case VALUE_INCOMPLETE_UNAVAILABLE -> authorship(AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW,
                    Reason.CURRENT_UNAVAILABLE);
            case WHOLE_STATE_CONFLICT -> authorship(AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW,
                    Reason.CURRENT_CONFLICT);
            case NO_KNOWN_CURRENT_STATE -> authorship(AuthorshipStage.CAN_PROCEED_TO_PLAN, Reason.NO_CURRENT_STATE);
            case SEMANTICALLY_UNAMBIGUOUS -> authorship(AuthorshipStage.CAN_PROCEED_TO_PLAN,
                    uniqueValue().status() == 1 ? Reason.ELIGIBLE : Reason.RESTORATION_INTENT_DEFERRED);
        };
    }

    private TokenValue uniqueValue() { return current.distinctReadableValues().iterator().next(); }
    private Authorship authorship(AuthorshipStage stage, Reason reason) {
        return new Authorship(stage, reason, current.currentHeadIds());
    }
}
