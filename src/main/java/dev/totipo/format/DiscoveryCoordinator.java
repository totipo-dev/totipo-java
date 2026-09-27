package dev.totipo.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * One established-client pass. Canonical VAULT unlock and §10 local establishment
 * are outer prerequisites. No persistence implementation, reset, policy execution,
 * provenance evaluation, or synchronized-storage writes.
 */
final class DiscoveryCoordinator {
    /** COMMITTED attests external durable insertion, including exact unscoped bytes. */
    @FunctionalInterface
    interface Committer {
        DurableKnowledgeState.PersistenceResult commit(AuthenticatedObservation observation) throws IOException;
    }

    private DiscoveryCoordinator() {}

    static DiscoveryResult discover(DiscoverySource source, byte[] establishedRoot,
                                    DurableKnowledgeState knowledge, Committer committer) {
        Objects.requireNonNull(committer);
        if (establishedRoot.length != 32) { throw new IllegalArgumentException("Requires established root key"); }
        DiscoverySource.Snapshot snapshot;
        try {
            snapshot = source.snapshot();
        } catch (IOException | SecurityException e) {
            snapshot = new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE);
        } catch (UnsupportedOperationException e) {
            snapshot = new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS);
        }
        var observations = new ArrayList<ObjectDiscovery.Observation>();
        var classifier = new ObjectDiscovery();
        boolean complete = snapshot.complete();
        boolean persistenceComplete = !knowledge.knowledgePersistenceBlocked();
        for (var candidate : snapshot.candidates()) {
            ObjectDiscovery.Observation observed;
            byte[] bytes;
            try (var handle = candidate.opener().open()) {
                bytes = BoundedObjectRead.read(handle);
            } catch (IOException | SecurityException e) {
                knowledge = knowledge.currentStorageFailure(candidate.id(),
                        DurableKnowledgeState.CurrentStorageFailure.UNREADABLE);
                observations.add(ObjectDiscovery.failure(candidate.id(), ObjectDiscovery.Classification.UNAVAILABLE,
                        ObjectDiscovery.Detail.IO_UNAVAILABLE));
                complete = false;
                continue;
            } catch (UnsupportedOperationException e) {
                knowledge = knowledge.currentStorageFailure(candidate.id(),
                        DurableKnowledgeState.CurrentStorageFailure.UNREADABLE);
                observations.add(ObjectDiscovery.failure(candidate.id(), ObjectDiscovery.Classification.UNAVAILABLE,
                        ObjectDiscovery.Detail.UNSUPPORTED_SAFE_OPEN));
                complete = false;
                continue;
            }
            observed = classifier.classify(candidate.id(), bytes, establishedRoot);
            observations.add(observed);
            if (observed.classification() == ObjectDiscovery.Classification.INVALID) {
                knowledge = knowledge.authenticatedInvalidSemantic(observed.id());
            } else if (observed.classification() == ObjectDiscovery.Classification.INVALID_STORAGE) {
                var reason = switch (observed.detail()) {
                    case WRONG_LENGTH -> DurableKnowledgeState.CurrentStorageFailure.WRONG_LENGTH;
                    case AEAD -> DurableKnowledgeState.CurrentStorageFailure.AEAD;
                    case PADDING -> DurableKnowledgeState.CurrentStorageFailure.PADDING;
                    case OBJECT_ID -> DurableKnowledgeState.CurrentStorageFailure.OBJECT_ID;
                    default -> throw new IllegalStateException("Unexpected storage failure");
                };
                knowledge = knowledge.currentStorageFailure(observed.id(), reason);
            } else if (observed.authenticated() != null) {
                var old = knowledge.record(observed.id());
                // Known exact records need no write. Known contradictions go through M2.0
                // without asking a backend to overwrite anything. COMMITTED here is never
                // used to insert an unknown record without the external attestation.
                var committed = DurableKnowledgeState.PersistenceResult.COMMITTED;
                if (old == null) {
                    try {
                        committed = Objects.requireNonNull(committer.commit(observed.authenticated()));
                    } catch (IOException e) {
                        committed = DurableKnowledgeState.PersistenceResult.FAILED;
                    }
                }
                var update = knowledge.afterPersistence(observed.authenticated(), committed);
                knowledge = update.state();
                if (committed == DurableKnowledgeState.PersistenceResult.FAILED
                        || update.outcome() == DurableKnowledgeState.Outcome.RECLASSIFICATION_REQUIRED) {
                    persistenceComplete = false;
                }
            }
        }
        var topology = new GraphTopology(knowledge);
        if (topology.integrity() == GraphIntegrityStatus.RESOLVED_CYCLE) {
            knowledge = knowledge.localSecurityMemoryCorruption();
        }
        var evidence = observations.stream().map(ObjectDiscovery.Observation::readable)
                .filter(Objects::nonNull)
                .filter(r -> r.routing().equals(topology.record(r.objectId()))).toList();
        return new DiscoveryResult(observations, snapshot.issue(), complete,
                complete && persistenceComplete ? DiscoveryState.READY : DiscoveryState.PROCESSING_INCOMPLETE,
                knowledge, topology, new CurrentReadableValues(topology, evidence));
    }
}
