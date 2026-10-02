package org.totipo;

import java.time.Instant;
import java.util.Objects;
/** Code and half-open validity interval at the supplied time. */
public record TotpCode(String code, Instant validFrom, Instant validUntil) {
    public TotpCode { Objects.requireNonNull(code); Objects.requireNonNull(validFrom); Objects.requireNonNull(validUntil); }
}
