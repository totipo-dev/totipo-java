package dev.totipo.format;

/** Snapshot facts for later UI disclosure, never additional candidate safety gates. */
enum CandidateWarning {
    NOT_ATTESTED_UNIQUELY_CURRENT,
    DISCOVERY_INCOMPLETE, OPAQUE_UNSCOPED_ACTIVE,
    CURRENT_OPAQUE_PRESENT, CURRENT_UNAVAILABLE_PRESENT, CURRENT_CONFLICT,
    CANDIDATE_HISTORICAL, CANDIDATE_CURRENT
}
