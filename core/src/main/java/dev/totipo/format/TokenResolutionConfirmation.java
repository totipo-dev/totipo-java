package dev.totipo.format;

import static dev.totipo.format.InitialTokenPublication.Status.*;

/**
 * Ephemeral §27 complete-state consent. Only prepare can construct this snapshot.
 * The serialized owner must advance revision for every head, availability, opaque,
 * displayed-provenance, discovery, continuity, persistence or identity event,
 * including change then revert. Revision must never wrap or be reused in a session.
 * No clock, wire evidence, candidate-use permission, or durable consent exists.
 */
final class TokenResolutionConfirmation {
    private final SecurityBytes tokenId;
    private final TokenValue desired;
    private final TokenUpdatePublication.Intent intent;
    private final CurrentTokenValueView view;
    private final InitialDeviceAdvertisement.Context owner;
    private final SecurityMemoryJournal.Replay head;
    private final DurableKnowledgeState knowledge;
    private final DeviceIdentityResult identity;
    private final SecurityBytes publicKey;
    private final long publicationEpoch;

    private TokenResolutionConfirmation(TokenUpdatePublication.Context context, DeviceIdentityResult identity,
            SecurityBytes tokenId, TokenValue desired, TokenUpdatePublication.Intent intent,
            CurrentTokenValueView view) {
        this.owner = context.owner();
        this.publicationEpoch = owner.session().tokenPublicationFence().epoch();
        this.head = owner.session().head();
        this.knowledge = owner.session().knowledge();
        this.identity = identity;
        this.publicKey = new SecurityBytes(identity.publicKeyX963(), 65);
        this.tokenId = tokenId;
        this.desired = desired;
        this.intent = intent;
        this.view = view;
    }

    record Preparation(InitialTokenPublication.Status status, CurrentTokenValueView current,
                       TokenResolutionConfirmation confirmation) {}

    /** Caller supplies the explicitly chosen complete result; never chooses an ancestor/peer. */
    static Preparation prepare(byte[] root, TokenUpdatePublication.Context context,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired,
            TokenUpdatePublication.Intent intent) {
        if (context.owner().session().tokenPublicationFence().reconciliationRequired()) {
            return new Preparation(RECONCILIATION_REQUIRED, null, null);
        }
        if (root.length != 32 || tokenId.size() != 32) {
            throw new IllegalArgumentException("Root/TOKEN_ID width");
        }
        var blocker = InitialTokenPublication.gate(context.owner(), root, identity);
        if (blocker != null) { return new Preparation(blocker, null, null); }
        var policy = TokenUpdatePublication.policy(context, tokenId);
        var view = policy.current();
        blocker = TokenUpdatePublication.blocker(policy);
        if (blocker == null) { return new Preparation(CONFIRMATION_NOT_REQUIRED, view, null); }
        if (blocker != CONFIRMATION_REQUIRED_CONFLICT && blocker != CONFIRMATION_REQUIRED_UNAVAILABLE) {
            return new Preparation(blocker, view, null);
        }
        if (desired == null) { return new Preparation(INVALID_VALUE, view, null); }
        try { TokenWriter.requireCapacity(desired, 0); }
        catch (IllegalArgumentException e) { return new Preparation(INVALID_VALUE, view, null); }
        // §30's distinct restoration requirement concerns an unambiguous tombstone.
        // Conflicting/unavailable lifecycle state uses §27. Explicit RESTORE is also
        // accepted for a chosen LIVE result, but never inferred or substituted.
        if (intent == null || intent == TokenUpdatePublication.Intent.RESTORE && desired.status() != 1) {
            return new Preparation(INVALID_UPDATE_INTENT, view, null);
        }
        return new Preparation(CONFIRMATION_PREPARED, view,
                new TokenResolutionConfirmation(context, identity, tokenId, desired, intent, view));
    }

    boolean fresh(byte[] root, TokenUpdatePublication.Context context, DeviceIdentityResult identity,
            SecurityBytes tokenId, TokenValue desired, TokenUpdatePublication.Intent intent) {
        var now = context.owner();
        return this.identity == identity && this.tokenId.equals(tokenId) && this.desired.equals(desired)
                && this.intent == intent && now.session() == owner.session()
                && !now.session().tokenPublicationFence().reconciliationRequired()
                && now.session().tokenPublicationFence().epoch() == publicationEpoch
                && now.revision() == owner.revision() && now.discovery() == owner.discovery()
                && now.session().head() == head && now.session().knowledge() == knowledge
                && InitialTokenPublication.gate(now, root, identity) == null
                && publicKey.equals(new SecurityBytes(identity.publicKeyX963(), 65))
                && view.equals(TokenUpdatePublication.policy(context, tokenId).current());
    }

    @Override public String toString() { return "TokenResolutionConfirmation[redacted]"; }
}
