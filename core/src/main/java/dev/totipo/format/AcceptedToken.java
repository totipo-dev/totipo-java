package dev.totipo.format;

import java.math.BigInteger;
import java.util.List;

/** Every component participates in record equality; contained byte values own their data. */
record AcceptedToken(ObjectId objectId, int objectVersion, SemanticStatus semanticStatus,
                      SecurityBytes tokenId, List<ObjectId> parents, SecurityBytes authorDeviceId,
                      BigInteger authorTime, TokenValue value) implements AcceptedObject {
    AcceptedToken {
        parents = List.copyOf(parents);
        if ((semanticStatus == SemanticStatus.SUPPORTED_VALID) != (value != null)) {
            throw new IllegalArgumentException("Supported TOKEN requires complete value");
        }
        AcceptedObject.checkNode(objectId, objectVersion, semanticStatus, tokenId, parents, authorTime);
        if (authorDeviceId.size() != 32) { throw new IllegalArgumentException("Invalid author identity"); }
    }
    @Override public String toString() {
        return "AcceptedToken[version=" + objectVersion + ", status=" + semanticStatus + ", parents=" + parents.size() + "]";
    }
}
