package dev.totipo.format;

import java.math.BigInteger;
import java.util.List;

/** Every component participates in record equality; contained byte values own their data. */
record KnownTokenNode(ObjectId objectId, int objectVersion, SemanticStatus semanticStatus,
                      SecurityBytes tokenId, List<ObjectId> parents, SecurityBytes authorDeviceId,
                      BigInteger authorTime) implements DurableRecord {
    KnownTokenNode {
        parents = List.copyOf(parents);
        DurableRecord.checkNode(objectId, objectVersion, semanticStatus, tokenId, parents, authorTime);
        if (authorDeviceId.size() != 32) { throw new IllegalArgumentException("Invalid author identity"); }
    }
    @Override public String toString() {
        return "KnownTokenNode[version=" + objectVersion + ", status=" + semanticStatus + ", parents=" + parents.size() + "]";
    }
}
