package dev.totipo.format;

import java.util.Objects;
import java.util.Optional;

/** Exact metadata belonging to one object, outside TokenValue equality. */
record TokenMetadata(Optional<String> clientName, Optional<UInt64> clientTime) {
    TokenMetadata {
        Objects.requireNonNull(clientName);
        Objects.requireNonNull(clientTime);
        clientName.ifPresent(name -> StrictUtf8.encode(name, 128));
    }
}
