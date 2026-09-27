package dev.totipo.format;

import java.util.Objects;

/** Exact encrypted object file, including the tag; no interpreted routing diagnostics. */
record OpaqueUnscopedRecord(ObjectId objectId, SecurityBytes exactObjectBytes) implements DurableRecord {
    OpaqueUnscopedRecord {
        Objects.requireNonNull(objectId);
        if (exactObjectBytes.size() != EnvelopeReader.OBJECT_BYTES) {
            throw new IllegalArgumentException("Requires all 1024 authenticated object bytes");
        }
    }
    @Override public String toString() { return "OpaqueUnscopedRecord[1024 bytes retained]"; }
}
