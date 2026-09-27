package dev.totipo.format;

import java.util.Objects;

/** Exact selection, not proof of availability; policy revalidates against supplied evidence. */
record CandidateToken(ObjectId objectId, SecurityBytes tokenId, TokenValue value) {
    CandidateToken {
        Objects.requireNonNull(objectId);
        Objects.requireNonNull(tokenId);
        Objects.requireNonNull(value);
        if (value.status() != 1) { throw new IllegalArgumentException("Candidate must be LIVE"); }
    }
    @Override public String toString() { return "CandidateToken[redacted]"; }
}
