package dev.totipo.format;

import java.io.IOException;
import java.util.Arrays;

/** Thread-confined synchronous semantic owner. After any ambiguous write failure,
 * reopen/replay is required. This class proves ordering, not disk durability. */
final class SecurityMemorySession {
    private final SecurityMemoryStorage storage;
    private SecurityMemoryJournal.Replay head;
    private DurableKnowledgeState knowledge;
    private boolean writeFailed;

    private SecurityMemorySession(SecurityMemoryStorage storage, SecurityMemoryJournal.Replay replay) {
        this.storage = storage; this.head = replay;
        this.knowledge = replay.status() == SecurityMemoryJournal.Status.CLEAN
                ? replay.knowledge() : replay.knowledge().persistenceBlocked();
    }
    static SecurityMemorySession open(SecurityMemoryStorage storage) throws IOException {
        try (var stream = storage.openRead()) {
            return new SecurityMemorySession(storage, SecurityMemoryJournal.replay(stream));
        }
    }
    /** Only for an explicitly new local configuration; create-new is enforced by storage. */
    static SecurityMemorySession initializeNew(SecurityMemoryStorage storage) throws IOException {
        storage.initializeDurably(SecurityMemoryJournal.header());
        return open(storage);
    }
    DurableKnowledgeState knowledge() { return knowledge; }
    SecurityMemoryJournal.Replay head() { return head; }
    LocalEstablishment establishment() { return head.establishment(); }

    boolean persistPending(byte[] binding) { return establish(LocalEstablishment.Phase.PENDING, binding, false); }
    boolean establishFromPending(byte[] binding) { return establish(LocalEstablishment.Phase.ESTABLISHED, binding, false); }
    boolean establishFirstOpen(byte[] binding) { return establish(LocalEstablishment.Phase.ESTABLISHED, binding, true); }
    private boolean establish(LocalEstablishment.Phase target, byte[] binding, boolean firstOpen) {
        var next = establishment().transition(target, new SecurityBytes(binding, 32));
        if (firstOpen && establishment().phase() == LocalEstablishment.Phase.PENDING
                || !firstOpen && target == LocalEstablishment.Phase.ESTABLISHED
                && establishment().phase() == LocalEstablishment.Phase.UNESTABLISHED) {
            throw new IllegalArgumentException("Wrong establishment operation");
        }
        if (next.equals(establishment())) { return writable(); }
        return append(target == LocalEstablishment.Phase.PENDING ? SecurityMemoryJournal.PENDING
                : SecurityMemoryJournal.ESTABLISHED, binding, next, knowledge);
    }
    DurableKnowledgeState.Update commit(AuthenticatedObservation observation) { return commitRecord(observation.record()); }
    /** Trusted internal record seam; not an authentication entry point. */
    DurableKnowledgeState.Update commitRecord(DurableRecord record) {
        if (establishment().phase() != LocalEstablishment.Phase.ESTABLISHED) {
            throw new IllegalStateException("Graph insertion requires establishment");
        }
        var proposal = knowledge.afterRecordPersistence(record, DurableKnowledgeState.PersistenceResult.COMMITTED);
        if (proposal.outcome() == DurableKnowledgeState.Outcome.UNCHANGED
                || proposal.outcome() == DurableKnowledgeState.Outcome.RECLASSIFICATION_REQUIRED) {
            // Retained opaque evidence needs a future explicit durable reclassification.
            // A scoped proposal is neither an insertion nor an integrity contradiction.
            return proposal;
        }
        if (knowledge.record(record.objectId()) != null) {
            markUnknown();
            return new DurableKnowledgeState.Update(knowledge, DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN);
        }
        if (!append(SecurityMemoryJournal.type(record), SecurityMemoryJournal.encode(record), establishment(), proposal.state())) {
            knowledge = knowledge.afterRecordPersistence(record, DurableKnowledgeState.PersistenceResult.FAILED).state();
            return new DurableKnowledgeState.Update(knowledge, DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED);
        }
        return new DurableKnowledgeState.Update(knowledge, proposal.outcome());
    }
    void authenticatedInvalidSemantic(ObjectId id) {
        if (knowledge.record(id) != null) { markUnknown(); }
    }
    boolean markUnknown() {
        if (knowledge.continuity() == LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN
                && head.knowledge().continuity() == LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN) { return writable(); }
        var blocked = knowledge.localSecurityMemoryCorruption();
        boolean success = append(SecurityMemoryJournal.UNKNOWN, new byte[0], establishment(), blocked);
        // This safety transition blocks immediately even if storage is entirely unwritable.
        knowledge = blocked;
        if (!success) { knowledge = knowledge.persistenceBlocked(); }
        return success;
    }
    private boolean writable() { return !writeFailed && head.status() == SecurityMemoryJournal.Status.CLEAN; }
    private boolean append(int type, byte[] payload, LocalEstablishment establishment, DurableKnowledgeState next) {
        if (!writable()) { return false; }
        byte[] frame = SecurityMemoryJournal.frame(Math.addExact(head.sequence(), 1), head.digest(), type, payload);
        try { storage.appendDurably(frame); }
        catch (IOException e) { writeFailed = true; return false; }
        knowledge = next;
        head = new SecurityMemoryJournal.Replay(SecurityMemoryJournal.Status.CLEAN, establishment, next,
                head.sequence() + 1, new SecurityBytes(Arrays.copyOfRange(frame, frame.length - 32, frame.length), 32),
                head.verifiedBytes() + frame.length, false);
        return true;
    }
    @Override public String toString() { return "SecurityMemorySession[" + head.status() + ", records=" + knowledge.size() + "]"; }
}
