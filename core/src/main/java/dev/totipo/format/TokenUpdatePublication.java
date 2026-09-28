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
        if (view.currentHeadIds().size() > TokenWriter.parentCapacity(desired)) {
            return fold(root, current, start, identity, tokenId, desired, authorTime, intent,
                    confirmation, view.currentHeadIds(), store, evidence, beforePublication);
        }
        return InitialTokenPublication.publishValue(root, start.owner().session(), identity, tokenId, desired, authorTime,
                DeviceWriter.canonicalParents(view.currentHeadIds()), store, evidence, () -> {
                    beforePublication.run();
                    return confirmation == null || confirmation.fresh(current.get(), tokenId, desired, intent);
                });
    }

    /** §47 linear carry; sorted original consumption is our deterministic choice. */
    private static InitialTokenPublication.Result fold(byte[] root, Supplier<Context> current, Context start,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, Collection<ObjectId> heads,
            V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforePublication) {
        var originals = heads.stream().sorted(java.util.Comparator.comparing(ObjectId::filename)).toList();
        int capacity = TokenWriter.parentCapacity(desired);
        byte[] time = authorTime.clone(), exactRoot = root.clone();
        var session = start.owner().session();
        try {
            beforePublication.run();
            if (confirmation != null && !confirmation.fresh(current.get(), tokenId, desired, intent)) {
                return InitialTokenPublication.failure(CONFIRMATION_STALE);
            }
            long expectedGeneration = session.generation(tokenId);
            ObjectId carry = null;
            InitialTokenPublication.Result result = null;
            for (int consumed = 0; consumed < originals.size();) {
                final long stageGeneration = expectedGeneration;
                java.util.function.BooleanSupplier fresh = () -> confirmation == null
                        || current.get().owner().session() == session && session.generation(tokenId) == stageGeneration;
                if (!fresh.getAsBoolean()) { return InitialTokenPublication.failure(CONFIRMATION_STALE); }
                var parents = new java.util.ArrayList<ObjectId>(capacity);
                if (carry != null) { parents.add(carry); }
                int end = Math.min(originals.size(), consumed + capacity - parents.size());
                parents.addAll(originals.subList(consumed, end));
                result = InitialTokenPublication.publishValue(exactRoot, session, identity, tokenId, desired, time,
                        DeviceWriter.canonicalParents(parents), store, evidence, fresh, false);
                if (result.receipt() == null) { return result; }
                carry = result.receipt().objectId();
                consumed = end;
                // Exempt only our one acknowledged acceptance, never external events during publication.
                expectedGeneration = Math.incrementExact(stageGeneration);
            }
            return new InitialTokenPublication.Result(TokenPublicationSuccessGate.allows(session, result.receipt(),
                    identity.publicKeyX963(), evidence) ? PUBLISHED_SUCCESS_READY : PUBLISHED_DEVICE_REQUIRED, result.receipt());
        } finally { java.util.Arrays.fill(exactRoot, (byte) 0); }
    }
}
