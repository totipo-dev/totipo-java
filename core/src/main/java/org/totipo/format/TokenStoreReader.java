package org.totipo.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;

/** Bounded validation over the platform discovery boundary; diagnostics never gate use. */
final class TokenStoreReader {
    private TokenStoreReader() {}

    static TokenStoreObservation read(DiscoverySource source, byte[] root) {
        Objects.requireNonNull(source);
        Objects.requireNonNull(root);
        var tokens = new ArrayList<ValidatedToken>();
        var candidates = new ArrayList<TokenStoreObservation.CandidateDiagnostic>();
        var snapshots = new ArrayList<DiscoverySource.SnapshotIssue>();
        try (var snapshot = source.snapshot()) {
            if (snapshot.issue() != DiscoverySource.SnapshotIssue.NONE) snapshots.add(snapshot.issue());
            for (var candidate : snapshot.candidates()) {
                try (var channel = candidate.opener().open()) {
                    byte[] bytes = BoundedObjectRead.read(channel);
                    var envelope = EnvelopeReader.open(candidate.id().filename(), bytes, root);
                    try {
                        if (envelope.status() != EnvelopeReader.Status.AUTHENTICATED_SEMANTIC) {
                            candidates.add(new TokenStoreObservation.CandidateDiagnostic(candidate.id(),
                                    TokenStoreObservation.Reason.INVALID_STORAGE));
                            continue;
                        }
                        byte[] semantic = envelope.semanticBytes();
                        try {
                            tokens.add(new ValidatedToken(candidate.id(), TokenReader.read(semantic)));
                        } catch (IllegalArgumentException invalid) {
                            candidates.add(new TokenStoreObservation.CandidateDiagnostic(candidate.id(),
                                    TokenStoreObservation.Reason.INVALID_TOKEN));
                        } finally {
                            Arrays.fill(semantic, (byte) 0);
                        }
                    } finally {
                        envelope.clear();
                    }
                } catch (IOException unavailable) {
                    candidates.add(new TokenStoreObservation.CandidateDiagnostic(candidate.id(),
                            TokenStoreObservation.Reason.UNAVAILABLE));
                }
            }
        } catch (IOException unavailable) {
            snapshots.add(DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE);
        }
        return new TokenStoreObservation(tokens, candidates, snapshots);
    }
}
