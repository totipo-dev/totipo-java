package dev.totipo.format;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Caller-supplied availability for one evaluation snapshot, from synchronized bytes
 * or trusted exact local copies. No storage source preference or automatic retention.
 * Build a fresh snapshot when availability changes; validation costs O(evidence size).
 */
final class CurrentReadableValues {
    private final GraphTopology topology;
    private final Map<ObjectId, ReadableTokenValue> values;

    CurrentReadableValues(GraphTopology topology, Collection<ReadableTokenValue> evidence) {
        this.topology = Objects.requireNonNull(topology);
        var indexed = new HashMap<ObjectId, ReadableTokenValue>();
        for (var item : evidence) {
            // Keys are derived only from authenticated identity, never supplied separately.
            if (!item.routing().equals(topology.record(item.objectId()))
                    || item.routing().semanticStatus() != SemanticStatus.SUPPORTED_VALID) {
                throw new IllegalStateException("Readable evidence contradicts durable routing");
            }
            var previous = indexed.putIfAbsent(item.objectId(), item);
            if (previous != null && !previous.value().equals(item.value())) {
                throw new IllegalStateException("Contradictory values for one authenticated OBJECT_ID");
            }
        }
        values = Map.copyOf(indexed);
    }

    void requireTopology(GraphTopology expected) {
        if (topology != expected) {
            throw new IllegalStateException("Availability validated against a different graph snapshot");
        }
    }

    ReadableTokenValue get(ObjectId id) { return values.get(id); }
}
