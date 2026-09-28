package dev.totipo.format;

import java.util.List;

record DiscoveryResult(List<ObjectDiscovery.Observation> observations,
                       DiscoverySource.SnapshotIssue snapshotIssue, AcceptedSnapshot snapshot) {
    DiscoveryResult { observations = List.copyOf(observations); }
    boolean resourceComplete() { return !snapshot.incomplete(); }
    DiscoveryState discoveryState() { return resourceComplete() ? DiscoveryState.READY : DiscoveryState.PROCESSING_INCOMPLETE; }
    GraphTopology topology() { return snapshot.topology(); }
}
