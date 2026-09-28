package dev.totipo.format;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Immutable §§22–24/31 topology derived only from an accepted snapshot.
 * Values and provenance do not select edges or heads. Head sets have no protocol order.
 */
final class GraphTopology {
    private record Identity(boolean token, SecurityBytes id) {}

    private final Map<ObjectId, Identity> identities;
    private final Map<ObjectId, List<ParentEdge>> edges;
    private final Map<ObjectId, List<ObjectId>> resolvedParents;
    private final Map<Identity, Set<ObjectId>> heads;
    private final GraphIntegrityStatus integrity;
    private final Map<ObjectId, AcceptedObject> records;

    GraphTopology(AcceptedSnapshot snapshot) {
        records = snapshot.objects();
        var ids = new HashMap<ObjectId, Identity>();
        var claims = new HashMap<ObjectId, List<ParentEdge>>();
        var parents = new HashMap<ObjectId, List<ObjectId>>();
        var frontier = new HashMap<Identity, Set<ObjectId>>();
        for (var entry : records.entrySet()) {
            var record = entry.getValue();
            if (!entry.getKey().equals(record.objectId())) {
                throw new IllegalArgumentException("Inconsistent OBJECT_ID index");
            }
            var identity = identity(record);
            if (identity != null) {
                ids.put(record.objectId(), identity);
                frontier.computeIfAbsent(identity, ignored -> new HashSet<>()).add(record.objectId());
            }
        }
        for (var id : ids.keySet()) {
            var child = records.get(id);
            var childEdges = new ArrayList<ParentEdge>();
            var childParents = new ArrayList<ObjectId>();
            for (var parent : parents(child)) {
                var status = classify(child, records.get(parent));
                childEdges.add(new ParentEdge(id, parent, status));
                if (status == ParentEdgeStatus.RESOLVED) {
                    childParents.add(parent);
                    frontier.get(ids.get(id)).remove(parent);
                }
            }
            claims.put(id, List.copyOf(childEdges));
            parents.put(id, List.copyOf(childParents));
        }
        identities = Map.copyOf(ids);
        edges = Map.copyOf(claims);
        resolvedParents = Map.copyOf(parents);
        var immutableHeads = new HashMap<Identity, Set<ObjectId>>();
        frontier.forEach((id, nodes) -> immutableHeads.put(id, Set.copyOf(nodes)));
        heads = Map.copyOf(immutableHeads);
        integrity = snapshot.conflictingEvidence() ? GraphIntegrityStatus.CONFLICTING_OBJECT_ID : hasCycle(parents) ? GraphIntegrityStatus.RESOLVED_CYCLE : GraphIntegrityStatus.ACYCLIC;
    }

    GraphIntegrityStatus integrity() { return integrity; }

    /** Immutable routing facts from the same snapshot that produced the heads. */
    AcceptedObject record(ObjectId id) { return records.get(id); }

    /** Diagnostics remain available even when a cycle prevents ordinary graph queries. */
    List<ParentEdge> parentEdges(ObjectId child) {
        return edges.getOrDefault(child, List.of());
    }

    /** Only actual parent claims have an edge status. */
    ParentEdgeStatus edgeStatus(ObjectId child, ObjectId parent) {
        return parentEdges(child).stream().filter(e -> e.parentObjectId().equals(parent))
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Not a scoped parent claim")).status();
    }

    /** Strict {@code A <c B}. Unknown, unscoped, cross-family and cross-identity pairs return false. */
    boolean ancestor(ObjectId a, ObjectId b) {
        requireAcyclic();
        if (a.equals(b) || !comparable(a, b)) { return false; }
        var visited = new HashSet<ObjectId>();
        var pending = new ArrayDeque<ObjectId>();
        pending.add(b);
        while (!pending.isEmpty()) {
            var next = pending.removeLast();
            if (!visited.add(next)) { continue; }
            for (var parent : resolvedParents.get(next)) {
                if (parent.equals(a)) { return true; }
                pending.add(parent);
            }
        }
        return false;
    }

    /** Distinct same-identity nodes only; noncomparable pairs are never concurrent. */
    boolean concurrent(ObjectId a, ObjectId b) {
        requireAcyclic();
        return !a.equals(b) && comparable(a, b) && !ancestor(a, b) && !ancestor(b, a);
    }

    Set<ObjectId> currentTokenHeads(SecurityBytes tokenId) {
        requireAcyclic();
        return heads.getOrDefault(new Identity(true, tokenId), Set.of());
    }

    Set<ObjectId> currentDeviceHeads(SecurityBytes deviceId) {
        requireAcyclic();
        return heads.getOrDefault(new Identity(false, deviceId), Set.of());
    }

    private boolean comparable(ObjectId a, ObjectId b) {
        var identity = identities.get(a);
        return identity != null && identity.equals(identities.get(b));
    }

    private void requireAcyclic() {
        if (integrity != GraphIntegrityStatus.ACYCLIC) {
            throw new IllegalStateException("Invalid accepted graph");
        }
    }

    private static Identity identity(AcceptedObject record) {
        if (record instanceof AcceptedToken t) { return new Identity(true, t.tokenId()); }
        if (record instanceof AcceptedDevice d) { return new Identity(false, d.deviceId()); }
        return null;
    }

    private static List<ObjectId> parents(AcceptedObject record) {
        if (record instanceof AcceptedToken t) { return t.parents(); }
        if (record instanceof AcceptedDevice d) { return d.parents(); }
        return List.of();
    }

    private static ParentEdgeStatus classify(AcceptedObject child, AcceptedObject parent) {
        var parentIdentity = identity(parent);
        // Opaque-unscoped evidence proves neither compatible nor wrong scoped identity.
        if (parentIdentity == null) { return ParentEdgeStatus.UNRESOLVED; }
        return parentIdentity.equals(identity(child)) ? ParentEdgeStatus.RESOLVED : ParentEdgeStatus.REJECTED;
    }

    /** Kahn elimination in child-to-parent direction; no recursion or ancestry closure. */
    private static boolean hasCycle(Map<ObjectId, List<ObjectId>> parents) {
        var children = new HashMap<ObjectId, Integer>();
        parents.keySet().forEach(id -> children.put(id, 0));
        parents.values().forEach(ps -> ps.forEach(p -> children.merge(p, 1, Integer::sum)));
        var pending = new ArrayDeque<ObjectId>();
        children.forEach((id, count) -> { if (count == 0) { pending.add(id); } });
        int removed = 0;
        while (!pending.isEmpty()) {
            var next = pending.removeLast();
            removed++;
            for (var parent : parents.get(next)) {
                if (children.merge(parent, -1, Integer::sum) == 0) { pending.add(parent); }
            }
        }
        return removed != parents.size();
    }

}
