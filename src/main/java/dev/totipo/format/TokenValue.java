package dev.totipo.format;

import java.util.Objects;

/** Exact §18 complete value. Java hashes are only in-memory collection aids. */
record TokenValue(int status, String issuer, String account, Credential credential) {
    TokenValue {
        Objects.requireNonNull(issuer);
        Objects.requireNonNull(account);
        Objects.requireNonNull(credential);
    }

    static TokenValue from(V1Plaintext.Token token) {
        var c = token.credential();
        byte[] secret = c.secret();
        return new TokenValue(token.status(), token.issuer(), token.account(),
                new Credential(c.algorithm(), c.digits(), c.period(), new SecurityBytes(secret, secret.length)));
    }

    /** Atomic credential equality includes every field, with owned content-equal bytes. */
    record Credential(int algorithm, int digits, long period, SecurityBytes secret) {
        Credential { Objects.requireNonNull(secret); }
        @Override public String toString() { return "Credential[redacted]"; }
    }

    @Override public String toString() { return "TokenValue[redacted]"; }
}
