package dev.totipo.format;

import java.math.BigInteger;
import java.util.List;

record AcceptedDevice(ObjectId objectId, int objectVersion, SemanticStatus semanticStatus,
                       SecurityBytes deviceId, List<ObjectId> parents, BigInteger authorTime,
                       SecurityBytes publicKeyX963, String displayName,
                       ProvenanceStatus provenance) implements AcceptedObject {
    AcceptedDevice(ObjectId objectId, int objectVersion, SemanticStatus semanticStatus,
                   SecurityBytes deviceId, List<ObjectId> parents, BigInteger authorTime,
                   SecurityBytes publicKeyX963) {
        this(objectId, objectVersion, semanticStatus, deviceId, parents, authorTime, publicKeyX963,
                semanticStatus == SemanticStatus.SUPPORTED_VALID ? "" : null, ProvenanceStatus.UNRESOLVED);
    }
    AcceptedDevice {
        parents = List.copyOf(parents);
        AcceptedObject.checkNode(objectId, objectVersion, semanticStatus, deviceId, parents, authorTime);
        if (semanticStatus == SemanticStatus.SUPPORTED_VALID
                ? publicKeyX963 == null || publicKeyX963.size() != 65 : publicKeyX963 != null) {
            throw new IllegalArgumentException("Impossible accepted DEVICE key");
        }
        java.util.Objects.requireNonNull(provenance);
        if (semanticStatus == SemanticStatus.SUPPORTED_VALID) { DeviceWriter.displayName(displayName); }
        else if (displayName != null || provenance != ProvenanceStatus.UNRESOLVED) {
            throw new IllegalArgumentException("Opaque DEVICE presentation");
        }
    }
    @Override public String toString() {
        return "AcceptedDevice[version=" + objectVersion + ", status=" + semanticStatus + ", parents=" + parents.size() + "]";
    }
}
