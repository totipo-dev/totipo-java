package dev.totipo.format;

/** Descriptive completeness only; none of these states grants operation eligibility. */
enum CurrentTokenValueState {
    NO_KNOWN_CURRENT_STATE,
    VALUE_INCOMPLETE_OPAQUE,
    VALUE_INCOMPLETE_UNAVAILABLE,
    SEMANTICALLY_UNAMBIGUOUS,
    WHOLE_STATE_CONFLICT
}
