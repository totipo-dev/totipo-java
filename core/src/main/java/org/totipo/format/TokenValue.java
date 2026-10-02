package org.totipo.format;

import java.util.Objects;

/** Java domain value; wire construction and validation are handled separately. Java hashes are only in-memory collection aids. */
record TokenValue(int status, String issuer, String account, Credential credential) {
    TokenValue {
        Objects.requireNonNull(issuer);
        Objects.requireNonNull(account);
        Objects.requireNonNull(credential);
    }

    /** Intrinsic v1 bounds, required by the complete TOKEN model and codec. */
    void validate() {
        if (status != 1 && status != 2) throw new IllegalArgumentException("Invalid status");
        StrictUtf8.encode(issuer, 256);
        StrictUtf8.encode(account, 256);
        if (credential.algorithm() < 1 || credential.algorithm() > 3
                || credential.digits() < 6 || credential.digits() > 8
                || credential.period() < 1 || credential.period() > 0xffff_ffffL
                || credential.secret().size() < 1 || credential.secret().size() > 128) {
            throw new IllegalArgumentException("Invalid credential");
        }
    }

    /** Atomic credential equality includes every field, with owned content-equal bytes. */
    record Credential(int algorithm, int digits, long period, SecurityBytes secret) {
        Credential { Objects.requireNonNull(secret); }
        @Override public String toString() { return "Credential[redacted]"; }
    }

    @Override public String toString() { return "TokenValue[redacted]"; }
}
