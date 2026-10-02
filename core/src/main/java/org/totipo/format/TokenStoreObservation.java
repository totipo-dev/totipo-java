package org.totipo.format;

import java.util.List;

/** Validated observed facts only; neither the observed set nor its history is certified. */
record TokenStoreObservation(List<ValidatedToken> validatedTokens,
                             List<CandidateDiagnostic> candidateDiagnostics,
                             List<DiscoverySource.SnapshotIssue> snapshotDiagnostics) {
    TokenStoreObservation {
        validatedTokens = List.copyOf(validatedTokens);
        candidateDiagnostics = List.copyOf(candidateDiagnostics);
        snapshotDiagnostics = List.copyOf(snapshotDiagnostics);
    }

    enum Reason { INVALID_STORAGE, INVALID_TOKEN, UNAVAILABLE }
    record CandidateDiagnostic(ObjectId objectId, Reason reason) {}
}
