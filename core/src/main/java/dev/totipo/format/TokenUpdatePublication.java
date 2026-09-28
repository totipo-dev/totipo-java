package dev.totipo.format;

import java.util.Collection;
import java.util.function.Supplier;
import static dev.totipo.format.InitialTokenPublication.Status.*;

/** Ordinary writes use the exact frontier selected before signing. No final-frontier transaction. */
final class TokenUpdatePublication {
    private TokenUpdatePublication() {}
    enum Intent { ORDINARY, RESTORE }
    record Context(InitialDeviceAdvertisement.Context owner) {
        AcceptedSnapshot snapshot() { return owner.session().snapshot(); }
    }
    static InitialTokenPublication.Result publish(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence) {
        return publish(root, current, identity, tokenId, desired, authorTime, intent, store, evidence, () -> {});
    }
    static InitialTokenPublication.Result publish(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforePublication) {
        return publishInternal(root, current, identity, tokenId, desired, authorTime, intent, null, store, evidence, beforePublication);
    }
    static InitialTokenPublication.Result publishConfirmed(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence) {
        return publishConfirmed(root, current, identity, tokenId, desired, authorTime, intent, confirmation, store, evidence, () -> {});
    }
    static InitialTokenPublication.Result publishConfirmed(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforePublication) {
        if (confirmation == null) { return InitialTokenPublication.failure(CONFIRMATION_STALE); }
        return publishInternal(root, current, identity, tokenId, desired, authorTime, intent, confirmation, store, evidence, beforePublication);
    }
    private static InitialTokenPublication.Result publishInternal(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforePublication) {
        var start = current.get();
        var blocker = InitialTokenPublication.gate(start.owner(), root, identity);
        if (blocker != null) { return InitialTokenPublication.failure(blocker); }
        if (confirmation != null && !confirmation.fresh(start, tokenId, desired, intent)) {
            return InitialTokenPublication.failure(CONFIRMATION_STALE);
        }
        var view = CurrentTokenValueEvaluator.evaluate(start.snapshot(), tokenId);
        if (view.state() == CurrentTokenValueState.OPAQUE_CURRENT) { return InitialTokenPublication.failure(CURRENT_OPAQUE_BLOCKED); }
        if (view.state() == CurrentTokenValueState.EMPTY) { return InitialTokenPublication.failure(NO_EXISTING_TOKEN); }
        if (view.state() == CurrentTokenValueState.CONFLICT && confirmation == null) {
            return InitialTokenPublication.failure(CONFIRMATION_REQUIRED_CONFLICT);
        }
        if (desired == null) { return InitialTokenPublication.failure(INVALID_VALUE); }
        if (intent == null) { return InitialTokenPublication.failure(INVALID_UPDATE_INTENT); }
        if (confirmation == null) {
            var old = view.distinctValues().iterator().next();
            boolean restore = old.status() == 2 && desired.status() == 1;
            if (restore && intent != Intent.RESTORE) { return InitialTokenPublication.failure(RESTORATION_INTENT_REQUIRED); }
            if (!restore && intent == Intent.RESTORE) { return InitialTokenPublication.failure(INVALID_UPDATE_INTENT); }
        }
        try { TokenWriter.requireCapacity(desired, 0); }
        catch (IllegalArgumentException e) { return InitialTokenPublication.failure(INVALID_VALUE); }
        try { TokenWriter.requireCapacity(desired, view.currentHeadIds().size()); }
        catch (IllegalArgumentException e) { return InitialTokenPublication.failure(FOLD_REQUIRED); }
        return InitialTokenPublication.publishValue(root, start.owner().session(), identity, tokenId, desired, authorTime,
                DeviceWriter.canonicalParents(view.currentHeadIds()), store, evidence, () -> {
                    beforePublication.run();
                    return confirmation == null || confirmation.fresh(current.get(), tokenId, desired, intent);
                });
    }
}
