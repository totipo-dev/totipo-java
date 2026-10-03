package org.totipo;

import java.util.Optional;
import java.util.Objects;
/** Exact client assertions, with an unsigned 64-bit time represented by raw long bits.
 * Name absence differs from a present empty string; text is not normalized.
 * Time absence differs from zero; negative long values retain unsigned high-bit values. */
public record ClientMetadata(Optional<String> clientName, Optional<Long> clientTimeBits) {
    public ClientMetadata { Objects.requireNonNull(clientName); Objects.requireNonNull(clientTimeBits); }
    public static ClientMetadata empty() { return new ClientMetadata(Optional.empty(), Optional.empty()); }
}

