package dev.totipo.format;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Per-TOKEN policy over current accepted evidence. */
final class TokenOperationPolicy {
    /** Diagnostics only, not serialized protocol state. */
    enum Reason {
        ELIGIBLE,
        NO_CURRENT_STATE, CURRENT_OPAQUE, CURRENT_CONFLICT,
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

    private final AcceptedSnapshot snapshot;
    private final CurrentTokenValueView current;
    private final Map<ObjectId, CandidateToken> candidates;
    TokenOperationPolicy(AcceptedSnapshot snapshot, SecurityBytes tokenId) {
        this.snapshot = snapshot;
        current = CurrentTokenValueEvaluator.evaluate(snapshot, tokenId);
        var catalog = new HashMap<ObjectId, CandidateToken>();
        for (var object : snapshot.objects().values()) {
            if (object instanceof AcceptedToken token && token.tokenId().equals(tokenId)
                    && token.value() != null && token.value().status() == 1) {
                catalog.put(token.objectId(), new CandidateToken(token.objectId(), tokenId, token.value()));
            }
        }
        candidates = Map.copyOf(catalog);
    }

    CurrentTokenValueView current() { return current; }
    /** Exact assertions, including historical ones; equal values do not collapse IDs. */
    Map<ObjectId, CandidateToken> candidates() { return candidates; }

    OrdinaryUse ordinaryUse() {
        var reason = switch (current.state()) {
            case EMPTY -> Reason.NO_CURRENT_STATE;
            case OPAQUE_CURRENT -> Reason.CURRENT_OPAQUE;
            case CONFLICT -> Reason.CURRENT_CONFLICT;
            case UNAMBIGUOUS -> uniqueValue().status() == 1 ? Reason.ELIGIBLE : Reason.CURRENT_TOMBSTONE;
        };
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
        if (snapshot.incomplete()) {
            facts.add(CandidateWarning.DISCOVERY_INCOMPLETE);
        }
        if (snapshot.hasUnscopedEvidence()) { facts.add(CandidateWarning.OPAQUE_UNSCOPED_ACTIVE); }
        if (!current.opaqueHeadIds().isEmpty()) { facts.add(CandidateWarning.CURRENT_OPAQUE_PRESENT); }
        // Known readable disagreement is worth disclosing even under incomplete state.
        if (current.distinctValues().size() > 1) { facts.add(CandidateWarning.CURRENT_CONFLICT); }
        return new CandidateUse(Reason.ELIGIBLE, selected, facts);
    }

    Authorship authorship() {
        return switch (current.state()) {
            case OPAQUE_CURRENT -> authorship(AuthorshipStage.BLOCKED, Reason.CURRENT_OPAQUE);
            case CONFLICT -> authorship(AuthorshipStage.REQUIRES_CONFIRMATION_WORKFLOW,
                    Reason.CURRENT_CONFLICT);
            case EMPTY -> authorship(AuthorshipStage.CAN_PROCEED_TO_PLAN, Reason.NO_CURRENT_STATE);
            case UNAMBIGUOUS -> authorship(AuthorshipStage.CAN_PROCEED_TO_PLAN,
                    uniqueValue().status() == 1 ? Reason.ELIGIBLE : Reason.RESTORATION_INTENT_DEFERRED);
        };
    }

    private TokenValue uniqueValue() { return current.distinctValues().iterator().next(); }
    private Authorship authorship(AuthorshipStage stage, Reason reason) {
        return new Authorship(stage, reason, current.currentHeadIds());
    }
}
