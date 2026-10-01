package dev.totipo.spi;

import java.util.Objects;
import java.util.OptionalLong;

/** Enumeration-time observations only; length is logical content bytes, not allocated size. */
public record ObjectEntry(ObjectName name, EntryKind kind, OptionalLong contentLength) {
    public ObjectEntry {
        Objects.requireNonNull(name); Objects.requireNonNull(kind); Objects.requireNonNull(contentLength);
        if (contentLength.isPresent() && contentLength.getAsLong() < 0) throw new IllegalArgumentException("Negative length");
    }
}
