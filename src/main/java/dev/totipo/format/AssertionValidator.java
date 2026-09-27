package dev.totipo.format;

import java.security.MessageDigest;
import java.util.Arrays;

/** §21.1 composition after envelope authentication and complete structural validation. */
final class AssertionValidator {
    private AssertionValidator() {}

    enum Status { ASSERTION_VALID, ASSERTION_INVALID }

    record Result(Status status, AssertionValidObject object) {}

    static Result validate(EnvelopeReader.Result authenticated) {
        if (authenticated.status() != EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE) {
            // Opaque future objects have no v1 assertion classification.
            throw new IllegalArgumentException("Requires authenticated supported-v1 structure");
        }
        var value = authenticated.plaintext();
        if (value.device() != null && !MessageDigest.isEqual(value.routing().identity(),
                P256.deviceId(value.device().publicKey()))) {
            return new Result(Status.ASSERTION_INVALID, null);
        }
        byte[] semantic = authenticated.semanticBytes();
        try {
            return new Result(Status.ASSERTION_VALID, new AssertionValidObject(value, semantic, authenticated.objectId()));
        } finally {
            Arrays.fill(semantic, (byte) 0);
        }
    }

    /** Only the validator can construct this immutable proof of intrinsic validity. */
    static final class AssertionValidObject {
        private final V1Plaintext plaintext;
        private final byte[] unsignedSemantic;
        private final ObjectId objectId;

        private AssertionValidObject(V1Plaintext plaintext, byte[] semantic, ObjectId objectId) {
            this.plaintext = plaintext;
            this.objectId = objectId;
            // Structural grammar guarantees the final complete SIGNATURE TLV.
            unsignedSemantic = Arrays.copyOf(semantic, semantic.length - 4 - plaintext.signature().length);
        }

        V1Plaintext plaintext() { return plaintext; }
        ObjectId objectId() { return objectId; }
        byte[] unsignedSemantic() { return unsignedSemantic.clone(); }
    }
}
