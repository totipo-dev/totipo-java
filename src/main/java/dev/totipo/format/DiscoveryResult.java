package dev.totipo.format;

import java.util.List;

/** Immutable coherent pass snapshot; raw observations are proposals, not durable acceptance. */
record DiscoveryResult(List<ObjectDiscovery.Observation> observations,
                       DiscoverySource.SnapshotIssue snapshotIssue, boolean resourceComplete,
                       DiscoveryState discoveryState, DurableKnowledgeState knowledge,
                       GraphTopology topology, CurrentReadableValues readable) {
    DiscoveryResult {
        observations = List.copyOf(observations);
        topology.requireKnowledge(knowledge);
        readable.requireTopology(topology);
    }
    @Override public String toString() {
        return "DiscoveryResult[candidates=" + observations.size() + ", resourceComplete="
                + resourceComplete + ", discoveryState=" + discoveryState + "]";
    }
}
