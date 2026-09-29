package dev.totipo.format;

import java.util.Objects;

/** Java domain value; wire construction and validation are handled separately. Java hashes are only in-memory collection aids. */
record TokenValue(int status, String issuer, String account, Credential credential) {
    TokenValue {
        Objects.requireNonNull(issuer);
        Objects.requireNonNull(account);
        Objects.requireNonNull(credential);
    }

    /** Atomic credential equality includes every field, with owned content-equal bytes. */
    record Credential(int algorithm, int digits, long period, SecurityBytes secret) {
        Credential { Objects.requireNonNull(secret); }
        @Override public String toString() { return "Credential[redacted]"; }
    }

    @Override public String toString() { return "TokenValue[redacted]"; }
}
