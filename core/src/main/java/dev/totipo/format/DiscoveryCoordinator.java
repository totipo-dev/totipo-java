package dev.totipo.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/** One independent discovery pass. Failed candidates never become accepted evidence. */
final class DiscoveryCoordinator {
    private DiscoveryCoordinator() {}
    static DiscoveryResult discover(DiscoverySource source, byte[] root) {
        return discover(source, root, new ObjectDiscovery());
    }
    static DiscoveryResult discover(DiscoverySource source, byte[] root, ObjectDiscovery classifier) {
        if (root.length != 32) { throw new IllegalArgumentException("Root width"); }
        DiscoverySource.Snapshot candidates;
        try { candidates = source.snapshot(); }
        catch (IOException | SecurityException e) {
            candidates = new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE);
        } catch (UnsupportedOperationException e) {
            candidates = new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS);
        }
        var observations = new ArrayList<ObjectDiscovery.Observation>();
        var accepted = new HashMap<ObjectId, AcceptedObject>();
        boolean complete = candidates.complete();
        try {
            for (var candidate : candidates.candidates()) {
                ObjectDiscovery.Observation observation;
                try (var input = candidate.opener().open()) {
                    observation = classifier.classify(candidate.id(), BoundedObjectRead.read(input), root);
                } catch (IOException | SecurityException | UnsupportedOperationException e) {
                    observation = ObjectDiscovery.failure(candidate.id(), ObjectDiscovery.Classification.UNAVAILABLE,
                            ObjectDiscovery.Detail.IO_UNAVAILABLE);
                    complete = false;
                }
                observations.add(observation);
                if (observation.authenticated() != null) {
                    var object = observation.authenticated().record();
                    var old = accepted.put(object.objectId(), object);
                    if (old != null && !AcceptedObject.sameEvidence(old, object)) { throw new IllegalStateException("Conflicting authenticated object identity"); }
                }
            }
        } finally {
            try { candidates.close(); } catch (IOException | SecurityException e) { complete = false; }
        }
        return new DiscoveryResult(observations, candidates.issue(), new AcceptedSnapshot(accepted, !complete));
    }
}
