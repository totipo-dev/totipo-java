package dev.totipo.format;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Current authenticated evidence; never serialized as local history. */
sealed interface AcceptedObject permits AcceptedToken, AcceptedDevice, OpaqueUnscopedRecord {
    ObjectId objectId();

    /** Reject impossible record construction; this does not validate an assertion. */
    static void checkNode(ObjectId id, int version, SemanticStatus status, SecurityBytes identity,
                          List<ObjectId> parents, BigInteger authorTime) {
        Objects.requireNonNull(id);
        Objects.requireNonNull(status);
        if (version < 0 || version > 255 || (version == 1) != (status == SemanticStatus.SUPPORTED_VALID)
                || identity.size() != 32 || authorTime.signum() < 0 || authorTime.bitLength() > 64) {
            throw new IllegalArgumentException("Impossible accepted routing record");
        }
        ObjectId previous = null;
        for (var parent : parents) {
            Objects.requireNonNull(parent);
            if (previous != null && Arrays.compareUnsigned(previous.bytes(), parent.bytes()) >= 0) {
                throw new IllegalArgumentException("Noncanonical accepted parent claims");
            }
            previous = parent;
        }
    }
}

