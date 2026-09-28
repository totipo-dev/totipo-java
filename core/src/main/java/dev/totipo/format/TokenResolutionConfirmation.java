package dev.totipo.format;

import static dev.totipo.format.InitialTokenPublication.Status.*;

/** Ephemeral consent bound only to the relevant TOKEN semantic decision in this session. */
final class TokenResolutionConfirmation {
    private final SnapshotSession session;
    private final SecurityBytes tokenId;
    private final TokenValue desired;
    private final TokenUpdatePublication.Intent intent;
    private final CurrentTokenValueView view;
    private final long generation;
    private TokenResolutionConfirmation(TokenUpdatePublication.Context context, SecurityBytes tokenId,
            TokenValue desired, TokenUpdatePublication.Intent intent, CurrentTokenValueView view) {
        this.session = context.owner().session(); this.tokenId = tokenId; this.desired = desired;
        this.intent = intent; this.view = view; this.generation = session.generation(tokenId);
    }
    record Preparation(InitialTokenPublication.Status status, CurrentTokenValueView current,
                       TokenResolutionConfirmation confirmation) {}
    static Preparation prepare(byte[] root, TokenUpdatePublication.Context context,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, TokenUpdatePublication.Intent intent) {
        var blocker = InitialTokenPublication.gate(context.owner(), root, identity);
        if (blocker != null) { return new Preparation(blocker, null, null); }
        var view = CurrentTokenValueEvaluator.evaluate(context.snapshot(), tokenId);
        if (view.state() == CurrentTokenValueState.OPAQUE_CURRENT) { return new Preparation(CURRENT_OPAQUE_BLOCKED, view, null); }
        if (view.state() != CurrentTokenValueState.CONFLICT) { return new Preparation(CONFIRMATION_NOT_REQUIRED, view, null); }
        if (desired == null) { return new Preparation(INVALID_VALUE, view, null); }
        try { TokenWriter.requireCapacity(desired, 0); }
        catch (IllegalArgumentException e) { return new Preparation(INVALID_VALUE, view, null); }
        if (intent == null || intent == TokenUpdatePublication.Intent.RESTORE && desired.status() != 1) {
            return new Preparation(INVALID_UPDATE_INTENT, view, null);
        }
        return new Preparation(CONFIRMATION_PREPARED, view, new TokenResolutionConfirmation(context, tokenId, desired, intent, view));
    }
    boolean fresh(TokenUpdatePublication.Context context, SecurityBytes tokenId, TokenValue desired,
                  TokenUpdatePublication.Intent intent) {
        return context.owner().session() == session && this.tokenId.equals(tokenId) && this.desired.equals(desired)
                && this.intent == intent && session.generation(tokenId) == generation
                && view.equals(CurrentTokenValueEvaluator.evaluate(context.snapshot(), tokenId));
    }
    @Override public String toString() { return "TokenResolutionConfirmation[redacted]"; }
}
