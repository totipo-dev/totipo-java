package dev.totipo.format;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collection;
import java.util.function.Supplier;
import static dev.totipo.format.InitialTokenPublication.Status.*;

/**
 * Ordinary whole-state updates under the DEVICE owner's serialized context contract.
 * The owner must advance revision on every safety/evidence/identity change, including
 * transient changes, and serialize the final recheck through publication and commit.
 * Revision includes displayed provenance changes (§27). No fold execution or TOKEN_ID entropy source.
 */
final class TokenUpdatePublication {
    private TokenUpdatePublication() {}

    enum Intent { ORDINARY, RESTORE }

    /** Immutable graph and current availability must describe the supplied owner snapshot. */
    record Context(InitialDeviceAdvertisement.Context owner, GraphTopology graph,
                   CurrentReadableValues readable) {}

    static InitialTokenPublication.Result publish(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence) {
        return publish(root, current, identity, tokenId, desired, authorTime, intent, store, evidence, () -> {});
    }

    static InitialTokenPublication.Result publish(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforeRecheck) {
        return publishInternal(root, current, identity, tokenId, desired, authorTime, intent, null,
                store, evidence, beforeRecheck);
    }

    static InitialTokenPublication.Result publishConfirmed(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence) {
        return publishConfirmed(root, current, identity, tokenId, desired, authorTime, intent, confirmation,
                store, evidence, () -> {});
    }

    static InitialTokenPublication.Result publishConfirmed(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforeRecheck) {
        if (confirmation == null) {
            return failure(current.get().owner().session().tokenPublicationFence().reconciliationRequired()
                    ? RECONCILIATION_REQUIRED : CONFIRMATION_STALE);
        }
        return publishInternal(root, current, identity, tokenId, desired, authorTime, intent, confirmation,
                store, evidence, beforeRecheck);
    }

    private static InitialTokenPublication.Result publishInternal(byte[] root, Supplier<Context> current,
            DeviceIdentityResult identity, SecurityBytes tokenId, TokenValue desired, byte[] authorTime,
            Intent intent, TokenResolutionConfirmation confirmation, V1ObjectPublicationStore store,
            Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence, Runnable beforeRecheck) {
        java.util.Objects.requireNonNull(store);
        byte[] exactRoot = root.clone(), time = authorTime.clone();
        byte[] semantic = null;
        try {
            if (exactRoot.length != 32 || time.length != 8 || tokenId.size() != 32) {
                throw new IllegalArgumentException("Root/TOKEN_ID/AUTHOR_TIME width");
            }
            var start = current.get();
            var fence = start.owner().session().tokenPublicationFence();
            if (fence.reconciliationRequired()) { return failure(RECONCILIATION_REQUIRED); }
            var publicationEpoch = fence.epoch();
            if (confirmation != null && !confirmation.fresh(exactRoot, start, identity, tokenId, desired, intent)) {
                return failure(CONFIRMATION_STALE);
            }
            var blocker = InitialTokenPublication.gate(start.owner(), exactRoot, identity);
            if (blocker != null) { return failure(blocker); }
            var policy = policy(start, tokenId);
            blocker = blocker(policy);
            if (blocker != null && confirmation == null) { return failure(blocker); }
            if (desired == null) { return failure(INVALID_VALUE); }
            // Separate invalid fields from a valid value whose required frontier cannot fit.
            try { TokenWriter.requireCapacity(desired, 0); }
            catch (IllegalArgumentException e) { return failure(INVALID_VALUE); }
            var view = policy.current();
            if (confirmation == null) {
                var old = view.distinctReadableValues().iterator().next();
                boolean restoration = old.status() == 2 && desired.status() == 1;
                if (intent == null || intent == Intent.RESTORE && !restoration) { return failure(INVALID_UPDATE_INTENT); }
                if (restoration && intent != Intent.RESTORE) { return failure(RESTORATION_INTENT_REQUIRED); }
            }
            try { TokenWriter.requireCapacity(desired, view.currentHeadIds().size()); }
            catch (IllegalArgumentException e) { return failure(FOLD_REQUIRED); }
            var parents = DeviceWriter.canonicalParents(view.currentHeadIds());
            var session = start.owner().session();
            var head = session.head();
            var knowledge = session.knowledge();
            byte[] key = identity.publicKeyX963();
            try { semantic = TokenWriter.signed(exactRoot, identity, tokenId.bytes(), desired, time, parents); }
            catch (GeneralSecurityException e) { return failure(SIGNING_FAILED); }
            catch (IllegalStateException e) { return failure(LOCAL_VALIDATION_FAILED); }
            var object = V1EnvelopeWriter.seal(exactRoot, semantic);
            var opened = EnvelopeReader.open(object.id().filename(), object.bytes(), exactRoot);
            if (opened.status() != EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE
                    || !Arrays.equals(semantic, opened.semanticBytes())
                    || !TokenWriter.matches(opened.plaintext(), tokenId.bytes(), key, desired, time, parents)) {
                return failure(LOCAL_VALIDATION_FAILED);
            }
            var assertion = AssertionValidator.validate(opened);
            if (assertion.status() != AssertionValidator.Status.ASSERTION_VALID
                    || ProvenanceEvaluator.evaluate(assertion.object(), exactRoot,
                    VerificationKeyMaterial.keys(key)) != ProvenanceStatus.VERIFIED) {
                return failure(LOCAL_VALIDATION_FAILED);
            }
            var observation = AuthenticatedObservation.supported(assertion.object());
            beforeRecheck.run();
            var now = current.get();
            if (fence.reconciliationRequired()) { return failure(RECONCILIATION_REQUIRED); }
            if (confirmation != null && !confirmation.fresh(exactRoot, now, identity, tokenId, desired, intent)) {
                return failure(CONFIRMATION_STALE);
            }
            if (now.owner().session() != session || now.owner().revision() != start.owner().revision()
                    || now.owner().discovery() != start.owner().discovery() || session.head() != head
                    || session.knowledge() != knowledge
                    || fence.epoch() != publicationEpoch
                    || InitialTokenPublication.gate(now.owner(), exactRoot, identity) != null) {
                return failure(OPERATION_STALE);
            }
            // Re-evaluate current bytes as well as heads: no ancestor/value fallback.
            var rechecked = policy(now, tokenId);
            if ((confirmation == null && blocker(rechecked) != null) || !rechecked.current().equals(view)
                    || !Arrays.equals(key, identity.publicKeyX963())) { return failure(OPERATION_STALE); }
            var publicationId = object.id();
            var publicationBytes = object.bytes();
            boolean acknowledged = false;
            try {
                if (store.publishDurably(publicationId, publicationBytes) == null) { return failure(PUBLICATION_INCOMPLETE); }
                acknowledged = true;
            } catch (IOException | RuntimeException e) { return failure(PUBLICATION_INCOMPLETE); }
            finally { if (!acknowledged) { fence.publicationUnacknowledged(); } }
            var update = session.commit(observation);
            if (update.outcome() != DurableKnowledgeState.Outcome.INSERTED
                    && update.outcome() != DurableKnowledgeState.Outcome.UNCHANGED) {
                return failure(KNOWLEDGE_PERSISTENCE_FAILED);
            }
            var node = (KnownTokenNode) observation.record();
            var receipt = new InitialTokenPublication.Receipt(node.tokenId(), node.objectId(), node.authorDeviceId());
            return new InitialTokenPublication.Result(TokenPublicationSuccessGate.allows(session, receipt, key, evidence)
                    ? PUBLISHED_AND_REMEMBERED_SUCCESS_READY : PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED, receipt);
        } finally {
            Arrays.fill(exactRoot, (byte) 0);
            if (semantic != null) { Arrays.fill(semantic, (byte) 0); }
        }
    }

    static TokenOperationPolicy policy(Context context, SecurityBytes tokenId) {
        return new TokenOperationPolicy(new VaultReadiness(context.owner().session().knowledge(),
                context.owner().discovery()), context.graph(), tokenId, context.readable());
    }

    static InitialTokenPublication.Status blocker(TokenOperationPolicy policy) {
        return switch (policy.authorship().reason()) {
            case ELIGIBLE, RESTORATION_INTENT_DEFERRED -> null;
            case NO_CURRENT_STATE -> NO_EXISTING_TOKEN;
            case CURRENT_OPAQUE -> CURRENT_OPAQUE_BLOCKED;
            case CURRENT_UNAVAILABLE -> CONFIRMATION_REQUIRED_UNAVAILABLE;
            case CURRENT_CONFLICT -> CONFIRMATION_REQUIRED_CONFLICT;
            default -> AUTHORSHIP_NOT_READY;
        };
    }

    private static InitialTokenPublication.Result failure(InitialTokenPublication.Status status) {
        return new InitialTokenPublication.Result(status, null);
    }
}
