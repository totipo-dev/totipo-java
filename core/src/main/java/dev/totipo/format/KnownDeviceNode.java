package dev.totipo.format;

import java.math.BigInteger;
import java.util.List;

record KnownDeviceNode(ObjectId objectId, int objectVersion, SemanticStatus semanticStatus,
                       SecurityBytes deviceId, List<ObjectId> parents, BigInteger authorTime,
                       SecurityBytes publicKeyX963) implements DurableRecord {
    KnownDeviceNode {
        parents = List.copyOf(parents);
        DurableRecord.checkNode(objectId, objectVersion, semanticStatus, deviceId, parents, authorTime);
        if (semanticStatus == SemanticStatus.SUPPORTED_VALID
                ? publicKeyX963 == null || publicKeyX963.size() != 65 : publicKeyX963 != null) {
            throw new IllegalArgumentException("Impossible durable DEVICE key");
        }
    }
}

