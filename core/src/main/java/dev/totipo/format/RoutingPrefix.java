package dev.totipo.format;

import java.math.BigInteger;
import java.util.List;

/** Frozen fields only; a prefix makes no claim about complete object validity. */
record RoutingPrefix(int version, int objectType, List<byte[]> parents,
                     BigInteger authorTime, byte[] identity, byte[] authorDeviceId) {
    RoutingPrefix {
        parents = copyParents(parents);
        identity = identity.clone();
        authorDeviceId = authorDeviceId == null ? null : authorDeviceId.clone();
    }

    @Override
    public List<byte[]> parents() {
        return copyParents(parents);
    }

    @Override
    public byte[] identity() {
        return identity.clone();
    }

    @Override
    public byte[] authorDeviceId() {
        return authorDeviceId == null ? null : authorDeviceId.clone();
    }

    private static List<byte[]> copyParents(List<byte[]> parents) {
        return parents.stream().map(byte[]::clone).toList();
    }
}
