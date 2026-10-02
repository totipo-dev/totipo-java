package org.totipo.spi;

import java.util.Objects;

/** Fresh exact-name/no-follow read, consuming at most expectedBytes + 1 content bytes.
 * Present requires the full exact length; no truncated prefix is returned.
 * Undersized requires observed EOF, Oversized an observed extra byte, Absent positive absence.
 * Present owns a defensive copy and returns copies; no array aliases cross this boundary. */
public sealed interface BoundedRead {
    record Present(byte[] bytes) implements BoundedRead {
        public Present { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }
    record Undersized(long observedLength) implements BoundedRead {
        public Undersized { if (observedLength < 0) throw new IllegalArgumentException("Negative length"); }
    }
    record Oversized() implements BoundedRead {}
    record Absent() implements BoundedRead {}
    record WrongKind(EntryKind kind) implements BoundedRead {
        public WrongKind { Objects.requireNonNull(kind); }
    }
    record Unavailable(StoreFailure reason) implements BoundedRead {
        public Unavailable { Objects.requireNonNull(reason); }
    }
}
