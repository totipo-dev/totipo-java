package dev.totipo.format;

import java.util.HashSet;
import java.util.Set;

/** Sensitive immutable state; sets have no protocol ordering. */
record CurrentTokenValueView(CurrentTokenValueState state, Set<ObjectId> currentHeadIds,
                             Set<ObjectId> opaqueHeadIds, Set<ObjectId> unavailableSupportedHeadIds,
                             Set<ObjectId> readableSupportedHeadIds, Set<TokenValue> distinctReadableValues) {
    CurrentTokenValueView {
        currentHeadIds = Set.copyOf(currentHeadIds);
        opaqueHeadIds = Set.copyOf(opaqueHeadIds);
        unavailableSupportedHeadIds = Set.copyOf(unavailableSupportedHeadIds);
        readableSupportedHeadIds = Set.copyOf(readableSupportedHeadIds);
        distinctReadableValues = Set.copyOf(distinctReadableValues);
        var union = new HashSet<>(opaqueHeadIds);
        union.addAll(unavailableSupportedHeadIds);
        union.addAll(readableSupportedHeadIds);
        if (!union.equals(currentHeadIds) || union.size() != opaqueHeadIds.size()
                + unavailableSupportedHeadIds.size() + readableSupportedHeadIds.size()
                || readableSupportedHeadIds.isEmpty() != distinctReadableValues.isEmpty()
                || distinctReadableValues.size() > readableSupportedHeadIds.size()) {
            throw new IllegalStateException("Invalid current value partition");
        }
    }

    @Override public String toString() { return "CurrentTokenValueView[state=" + state + ", values=redacted]"; }
}
