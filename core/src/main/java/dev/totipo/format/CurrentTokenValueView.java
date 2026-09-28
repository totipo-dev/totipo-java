package dev.totipo.format;

import java.util.Set;

record CurrentTokenValueView(CurrentTokenValueState state, Set<ObjectId> currentHeadIds,
                             Set<ObjectId> opaqueHeadIds, Set<TokenValue> distinctValues) {
    CurrentTokenValueView {
        currentHeadIds = Set.copyOf(currentHeadIds);
        opaqueHeadIds = Set.copyOf(opaqueHeadIds);
        distinctValues = Set.copyOf(distinctValues);
    }
    @Override public String toString() { return "CurrentTokenValueView[state=" + state + ", values=redacted]"; }
}
