package dev.totipo.format;

import java.math.BigInteger;
import java.util.List;

record AcceptedDevice(ObjectId objectId, int objectVersion, SemanticStatus semanticStatus,
                       SecurityBytes deviceId, List<ObjectId> parents, BigInteger authorTime,
                       SecurityBytes publicKeyX963) implements AcceptedObject {
    AcceptedDevice {
        parents = List.copyOf(parents);
        AcceptedObject.checkNode(objectId, objectVersion, semanticStatus, deviceId, parents, authorTime);
        if (semanticStatus == SemanticStatus.SUPPORTED_VALID
                ? publicKeyX963 == null || publicKeyX963.size() != 65 : publicKeyX963 != null) {
            throw new IllegalArgumentException("Impossible accepted DEVICE key");
        }
    }
    @Override public String toString() {
        return "AcceptedDevice[version=" + objectVersion + ", status=" + semanticStatus + ", parents=" + parents.size() + "]";
    }
}
