package dev.totipo.format;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Current authenticated evidence; never serialized as local history. */
sealed interface AcceptedObject permits AcceptedToken, AcceptedDevice, OpaqueUnscopedRecord {
    ObjectId objectId();

    /** Temporary verification availability is not a different authenticated meaning. */
    static boolean sameEvidence(AcceptedObject a, AcceptedObject b) {
        if (a instanceof AcceptedDevice d && b instanceof AcceptedDevice e) {
            return d.objectId().equals(e.objectId()) && d.objectVersion() == e.objectVersion()
                    && d.semanticStatus() == e.semanticStatus() && d.deviceId().equals(e.deviceId())
                    && d.parents().equals(e.parents()) && d.authorTime().equals(e.authorTime())
                    && Objects.equals(d.publicKeyX963(), e.publicKeyX963()) && Objects.equals(d.displayName(), e.displayName());
        }
        return a.equals(b);
    }

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
