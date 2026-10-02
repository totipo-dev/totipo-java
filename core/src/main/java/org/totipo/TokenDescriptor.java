package org.totipo;

import java.time.Duration;
import java.util.Objects;
public record TokenDescriptor(TokenStatus status, String issuer, String account,
        TotpAlgorithm algorithm, int digits, Duration period) {
    public TokenDescriptor {
        Objects.requireNonNull(status); Objects.requireNonNull(issuer); Objects.requireNonNull(account);
        Objects.requireNonNull(algorithm); Objects.requireNonNull(period);
        if (digits < 6 || digits > 8 || period.getNano() != 0 || period.getSeconds() < 1
                || period.getSeconds() > 0xffff_ffffL) throw new IllegalArgumentException("Credential bounds");
    }
}

