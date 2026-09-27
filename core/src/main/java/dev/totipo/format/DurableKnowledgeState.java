package dev.totipo.format;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable model of an established client's persisted security knowledge (§§24,34).
 * This class performs no persistence and proves no crash durability. One instance belongs
 * to one externally bound vault/continuity epoch; there is deliberately no reset operation.
 */
final class DurableKnowledgeState {
    enum Outcome { INSERTED, UNCHANGED, LOCAL_CONTINUITY_UNKNOWN, RECLASSIFICATION_REQUIRED, PERSISTENCE_BLOCKED }
    enum PersistenceResult { COMMITTED, FAILED }
    /** Exactly the benign §24.7 / portable remote-unavailable reasons. */
    enum CurrentStorageFailure { ABSENT, UNREADABLE, WRONG_LENGTH, AEAD, PADDING, OBJECT_ID }
    record Update(DurableKnowledgeState state, Outcome outcome) {}

    private final IdIndex index;
    private final int size;
    private final LocalContinuityStatus continuity;
    private final boolean knowledgePersistenceBlocked;

    private DurableKnowledgeState(IdIndex index, int size, LocalContinuityStatus continuity, boolean blocked) {
        this.index = index;
        this.size = size;
        this.continuity = continuity;
        this.knowledgePersistenceBlocked = blocked;
    }

    static DurableKnowledgeState establishedEmpty() {
        return new DurableKnowledgeState(IdIndex.EMPTY, 0, LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN, false);
    }

    int size() { return size; }
    DurableRecord record(ObjectId id) { return index.get(id); }
    LocalContinuityStatus continuity() { return continuity; }
    boolean knowledgePersistenceBlocked() { return knowledgePersistenceBlocked; }

    /** Explicit inspection snapshot; ingestion does not enumerate existing records. */
    Map<ObjectId, DurableRecord> records() { return index.snapshot(); }

    /**
     * Call only after the future persistence layer reports the insertion outcome.
     * COMMITTED attests that the security record (including exact unscoped bytes) was
     * committed. Merely observing/parsing an object is not such an attestation.
     */
    Update afterPersistence(AuthenticatedObservation observation, PersistenceResult persistence) {
        return afterRecordPersistence(observation.record(), persistence);
    }

    /**
     * Internal consistency seam for trusted durable-record integration and symbolic tests.
     * It is NOT an authentication entry point. Tests may use this to exercise impossible
     * collisions/corrupt-memory branches without claiming to create cryptographic collisions.
     */
    Update afterRecordPersistence(DurableRecord incoming, PersistenceResult persistence) {
        Objects.requireNonNull(persistence);
        var old = record(incoming.objectId());
        if (incoming.equals(old)) { return new Update(this, Outcome.UNCHANGED); }
        if (old instanceof OpaqueUnscopedRecord && !(incoming instanceof OpaqueUnscopedRecord)) {
            // A dedicated future transition must verify exact retained evidence and commit
            // its compatible reclassification. Ordinary ingestion cannot perform it.
            return new Update(this, Outcome.RECLASSIFICATION_REQUIRED);
        }
        if (old != null) {
            return new Update(localSecurityMemoryCorruption(), Outcome.LOCAL_CONTINUITY_UNKNOWN);
        }
        if (persistence == PersistenceResult.FAILED) {
            return new Update(new DurableKnowledgeState(index, size, continuity, true), Outcome.PERSISTENCE_BLOCKED);
        }
        var committed = new DurableKnowledgeState(index.put(incoming), size + 1, continuity,
                knowledgePersistenceBlocked);
        if (GraphTopology.insertionClosesCycle(incoming, committed)) {
            return new Update(committed.localSecurityMemoryCorruption(), Outcome.LOCAL_CONTINUITY_UNKNOWN);
        }
        return new Update(committed, Outcome.INSERTED);
    }

    /** Includes externally detected malformed records, rollback, or inconsistent local memory. */
    DurableKnowledgeState localSecurityMemoryCorruption() {
        return new DurableKnowledgeState(index, size, LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN,
                knowledgePersistenceBlocked);
    }

    /**
     * Trusted classification seam, not an authentication entry point. Invoke only after
     * envelope authentication, padding and keyed-ID checks succeeded, but supported
     * semantic validation failed. The ID must be the authenticated ID, not a pathname claim.
     * At an unknown ID this creates no knowledge. At a known ID it cannot reproduce the
     * remembered valid/routable/evidence classification and is a §24.7 integrity failure.
     * Like afterRecordPersistence, this also permits defensive corrupt-memory tests
     * without manufacturing a cryptographic collision.
     */
    DurableKnowledgeState authenticatedInvalidSemantic(ObjectId authenticatedId) {
        Objects.requireNonNull(authenticatedId);
        return record(authenticatedId) == null ? this : localSecurityMemoryCorruption();
    }

    /**
     * Current synchronized storage is not the durable security-memory store.
     * None of these reasons establishes authenticated keyed-ID-consistent disagreement.
     * Semantic invalidity after successful identity authentication belongs to
     * authenticatedInvalidSemantic; conflicting classified records use afterRecordPersistence.
     */
    DurableKnowledgeState currentStorageFailure(ObjectId id, CurrentStorageFailure failure) {
        Objects.requireNonNull(id);
        Objects.requireNonNull(failure);
        return this;
    }

    /**
     * Fixed-depth byte-key index. Copies at most 32 bounded maps per insertion, never all
     * known records. This is an identity index, not parent-link traversal or a graph engine.
     */
    private record IdIndex(Map<Byte, IdIndex> children, DurableRecord value) {
        private static final IdIndex EMPTY = new IdIndex(Map.of(), null);

        DurableRecord get(ObjectId id) {
            var cursor = this;
            for (byte part : id.bytes()) {
                cursor = cursor.children.get(part);
                if (cursor == null) { return null; }
            }
            return cursor.value;
        }

        IdIndex put(DurableRecord record) {
            byte[] key = record.objectId().bytes();
            var path = new ArrayList<IdIndex>(32);
            var cursor = this;
            for (byte part : key) {
                path.add(cursor);
                cursor = cursor.children.getOrDefault(part, EMPTY);
            }
            var replacement = new IdIndex(Map.of(), record);
            for (int i = key.length - 1; i >= 0; i--) {
                var children = new HashMap<>(path.get(i).children);
                children.put(key[i], replacement);
                replacement = new IdIndex(Map.copyOf(children), null);
            }
            return replacement;
        }

        Map<ObjectId, DurableRecord> snapshot() {
            var result = new HashMap<ObjectId, DurableRecord>();
            var pending = new ArrayDeque<IdIndex>();
            pending.add(this);
            while (!pending.isEmpty()) {
                var next = pending.removeLast();
                if (next.value != null) { result.put(next.value.objectId(), next.value); }
                pending.addAll(next.children.values());
            }
            return Map.copyOf(result);
        }
    }
}
