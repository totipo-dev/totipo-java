package org.totipo;

import java.util.List;
import java.util.Objects;
/** Knowledge of the entire frozen operation, never remote synchronization status. */
public sealed interface SaveResult permits PartialSaveResult, SaveResult.AdditionalConflict {
    /** Every required immutable object received a configured-store durability acknowledgement. */
    record Saved(TokenId tokenId, List<RevisionId> revisions) implements RetryResult {
        public Saved { Objects.requireNonNull(tokenId); revisions = List.copyOf(revisions); }
    }
    /** Nothing published; independently owned original partial resolution is available. */
    record AdditionalConflict(VaultState latest, PartialResolution resolution) implements SaveResult {
        public AdditionalConflict { Objects.requireNonNull(latest); Objects.requireNonNull(resolution); }
    }
    /** Definitely no potentially successful persistence point for this operation. */
    record Failed(Reason reason) implements PartialSaveResult {
        public Failed { Objects.requireNonNull(reason); }
    }
    /** May already have persisted. Later failed retries cannot downgrade this to Failed. */
    record PublicationUncertain(PublicationRetry retry) implements RetryResult {
        public PublicationUncertain { Objects.requireNonNull(retry); }
    }
    enum Reason { OBSERVATION_UNAVAILABLE, UNRESOLVED_FIELDS, SESSION_CLOSING, PREPARATION_FAILED }
}
