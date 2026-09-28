package dev.totipo.format;

import java.util.Objects;

/** Reusable classification of one owned bounded byte observation, independent of storage/state. */
final class ObjectDiscovery {
    enum Classification { SUPPORTED_VALID, OPAQUE_ROUTABLE, OPAQUE_UNSCOPED, INVALID, INVALID_STORAGE, UNAVAILABLE }
    enum Detail { NONE, WRONG_LENGTH, AEAD, PADDING, OBJECT_ID, SEMANTIC, IO_UNAVAILABLE, UNSUPPORTED_SAFE_OPEN }

    record Observation(ObjectId id, Classification classification, Detail detail,
                       AuthenticatedObservation authenticated) {
        @Override public String toString() {
            return "Observation[" + id.filename() + ", " + classification + ", " + detail + "]";
        }
    }

    @FunctionalInterface
    interface EnvelopeOpener { EnvelopeReader.Result open(String name, byte[] bytes, byte[] root); }
    private final EnvelopeOpener envelopes;

    ObjectDiscovery() { this(EnvelopeReader::open); }
    // Test seam proving size rejection precedes any invocation of the envelope pipeline.
    ObjectDiscovery(EnvelopeOpener envelopes) { this.envelopes = Objects.requireNonNull(envelopes); }

    Observation classify(ObjectId id, byte[] bytes, byte[] establishedRoot) {
        if (bytes.length != EnvelopeReader.OBJECT_BYTES) {
            return failure(id, Classification.INVALID_STORAGE, Detail.WRONG_LENGTH);
        }
        var envelope = envelopes.open(id.filename(), bytes, establishedRoot);
        return switch (envelope.status()) {
            case INVALID_ENVELOPE -> failure(id, Classification.INVALID_STORAGE, Detail.PADDING);
            case AUTHENTICATION_FAILED -> failure(id, Classification.INVALID_STORAGE, Detail.AEAD);
            case OBJECT_ID_MISMATCH -> failure(id, Classification.INVALID_STORAGE, Detail.OBJECT_ID);
            case AUTHENTICATED_INVALID_STRUCTURE -> failure(id, Classification.INVALID, Detail.SEMANTIC);
            case AUTHENTICATED_FUTURE_TOKEN, AUTHENTICATED_FUTURE_DEVICE, AUTHENTICATED_OPAQUE_UNSCOPED ->
                new Observation(id, envelope.status() == EnvelopeReader.Status.AUTHENTICATED_OPAQUE_UNSCOPED
                        ? Classification.OPAQUE_UNSCOPED : Classification.OPAQUE_ROUTABLE,
                        Detail.NONE, AuthenticatedObservation.opaque(envelope).orElseThrow());
            case AUTHENTICATED_V1_STRUCTURE -> {
                var assertion = AssertionValidator.validate(envelope);
                if (assertion.status() != AssertionValidator.Status.ASSERTION_VALID) {
                    yield failure(id, Classification.INVALID, Detail.SEMANTIC);
                }
                yield new Observation(id, Classification.SUPPORTED_VALID, Detail.NONE,
                        AuthenticatedObservation.supported(assertion.object()));
            }
        };
    }

    static Observation failure(ObjectId id, Classification classification, Detail detail) {
        return new Observation(id, classification, detail, null);
    }
}
