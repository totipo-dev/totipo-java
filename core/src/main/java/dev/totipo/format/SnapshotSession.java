package dev.totipo.format;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/** Thread-confined current state and TOKEN-specific consent generations. No persistence. */
final class SnapshotSession {
    private final SecurityBytes binding;
    private AcceptedSnapshot snapshot = AcceptedSnapshot.empty();
    private final Map<SecurityBytes, Long> generations = new HashMap<>();
    SnapshotSession(SecurityBytes binding) {
        if (binding.size() != 32) { throw new IllegalArgumentException("Binding width"); }
        this.binding = binding;
    }
    SecurityBytes binding() { return binding; }
    AcceptedSnapshot snapshot() { return snapshot; }
    long generation(SecurityBytes tokenId) { return generations.getOrDefault(tokenId, 0L); }
    void replace(AcceptedSnapshot next) {
        var changed = new HashSet<SecurityBytes>();
        for (var object : next.objects().values()) {
            if (object instanceof AcceptedToken token && !token.equals(snapshot.object(token.objectId()))) {
                changed.add(token.tokenId());
            }
        }
        // Also observe removals: disappearance can materially alter the visible decision.
        for (var object : snapshot.objects().values()) {
            if (object instanceof AcceptedToken token && !token.equals(next.object(token.objectId()))) {
                changed.add(token.tokenId());
            }
        }
        changed.forEach(id -> generations.put(id, Math.incrementExact(generation(id))));
        snapshot = next;
    }
    void accept(AcceptedObject object) { replace(snapshot.accepting(object)); }
}
