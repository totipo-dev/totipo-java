package dev.totipo.format;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

/** Initial roots only. Uses the DEVICE owner's serialized context/revision contract. */
final class InitialTokenPublication {
    private InitialTokenPublication() {}
    enum Status {
        PUBLISHED_AND_REMEMBERED_SUCCESS_READY, PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED,
        AUTHORSHIP_NOT_READY, LOCAL_STATE_NOT_ESTABLISHED, DEVICE_IDENTITY_UNAVAILABLE,
        DEVICE_IDENTITY_BINDING_MISMATCH, TOKEN_ID_COLLISION, INVALID_VALUE,
        SIGNING_FAILED, LOCAL_VALIDATION_FAILED, OPERATION_STALE,
        PUBLICATION_INCOMPLETE, KNOWLEDGE_PERSISTENCE_FAILED,
        NO_EXISTING_TOKEN, CURRENT_OPAQUE_BLOCKED, CONFIRMATION_REQUIRED_CONFLICT,
        CONFIRMATION_REQUIRED_UNAVAILABLE, RESTORATION_INTENT_REQUIRED,
        INVALID_UPDATE_INTENT, FOLD_REQUIRED
    }
    record Receipt(SecurityBytes tokenId, ObjectId objectId, SecurityBytes authorDeviceId) {}
    record Result(Status status, Receipt receipt) {}
    private static Result failure(Status status) { return new Result(status, null); }

    static Result publish(byte[] root, Supplier<InitialDeviceAdvertisement.Context> current,
                          DeviceIdentityResult identity, TokenValue value, byte[] authorTime,
                          V1ObjectPublicationStore store,
                          Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence) {
        return publish(root, current, identity, value, authorTime, store, evidence, new EntropySource.Jdk(), () -> {});
    }

    static Result publish(byte[] root, Supplier<InitialDeviceAdvertisement.Context> current,
                          DeviceIdentityResult identity, TokenValue value, byte[] authorTime,
                          V1ObjectPublicationStore store,
                          Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence,
                          EntropySource entropy, Runnable beforeRecheck) {
        // TokenValue and SecurityBytes are immutable and already own credential input.
        byte[] exactRoot = root.clone(), time = authorTime.clone();
        byte[] semantic = null;
        if (exactRoot.length != 32 || time.length != 8) {
            Arrays.fill(exactRoot, (byte) 0);
            throw new IllegalArgumentException("Root/AUTHOR_TIME width");
        }
        try {
            var start = current.get();
            Status blocker = gate(start, exactRoot, identity);
            if (blocker != null) { return failure(blocker); }
            try { TokenWriter.requireCapacity(value, 0); }
            catch (IllegalArgumentException e) { return failure(Status.INVALID_VALUE); }
            var session = start.session();
            var head = session.head();
            var knowledge = session.knowledge();
            byte[] id = new byte[32]; entropy.fill(id);
            var tokenId = new SecurityBytes(id, 32);
            if (hasHistory(session, tokenId)) { return failure(Status.TOKEN_ID_COLLISION); }
            byte[] key = identity.publicKeyX963();
            try { semantic = TokenWriter.signed(exactRoot, identity, id, value, time, List.of()); }
            catch (GeneralSecurityException e) { return failure(Status.SIGNING_FAILED); }
            catch (IllegalStateException e) { return failure(Status.LOCAL_VALIDATION_FAILED); }
            var object = V1EnvelopeWriter.seal(exactRoot, semantic);
            var opened = EnvelopeReader.open(object.id().filename(), object.bytes(), exactRoot);
            if (opened.status() != EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE
                    || !Arrays.equals(semantic, opened.semanticBytes())
                    || !TokenWriter.matches(opened.plaintext(), id, key, value, time, List.of())) {
                return failure(Status.LOCAL_VALIDATION_FAILED);
            }
            var assertion = AssertionValidator.validate(opened);
            if (assertion.status() != AssertionValidator.Status.ASSERTION_VALID
                    || ProvenanceEvaluator.evaluate(assertion.object(), exactRoot,
                    VerificationKeyMaterial.keys(key)) != ProvenanceStatus.VERIFIED) {
                return failure(Status.LOCAL_VALIDATION_FAILED);
            }
            var observation = AuthenticatedObservation.supported(assertion.object());
            beforeRecheck.run();
            var now = current.get();
            if (now.session() != session || now.revision() != start.revision()
                    || now.discovery() != start.discovery() || session.head() != head
                    || session.knowledge() != knowledge || gate(now, exactRoot, identity) != null
                    || hasHistory(session, tokenId)) { return failure(Status.OPERATION_STALE); }
            try {
                if (store.publishDurably(object.id(), object.bytes()) == null) {
                    return failure(Status.PUBLICATION_INCOMPLETE);
                }
            } catch (IOException e) { return failure(Status.PUBLICATION_INCOMPLETE); }
            var update = session.commit(observation);
            if (update.outcome() != DurableKnowledgeState.Outcome.INSERTED
                    && update.outcome() != DurableKnowledgeState.Outcome.UNCHANGED) {
                return failure(Status.KNOWLEDGE_PERSISTENCE_FAILED);
            }
            var node = (KnownTokenNode) observation.record();
            var receipt = new Receipt(node.tokenId(), node.objectId(), node.authorDeviceId());
            return new Result(TokenPublicationSuccessGate.allows(session, receipt, key, evidence)
                    ? Status.PUBLISHED_AND_REMEMBERED_SUCCESS_READY
                    : Status.PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED, receipt);
        } finally {
            Arrays.fill(exactRoot, (byte) 0);
            if (semantic != null) { Arrays.fill(semantic, (byte) 0); }
        }
    }

    private static boolean hasHistory(SecurityMemorySession session, SecurityBytes id) {
        return session.knowledge().records().values().stream()
                .anyMatch(r -> r instanceof KnownTokenNode t && t.tokenId().equals(id));
    }

    static Status gate(InitialDeviceAdvertisement.Context context, byte[] root, DeviceIdentityResult identity) {
        var session = context.session();
        if (session.head().status() != SecurityMemoryJournal.Status.CLEAN
                || session.establishment().phase() != LocalEstablishment.Phase.ESTABLISHED) {
            return Status.LOCAL_STATE_NOT_ESTABLISHED;
        }
        if (!new VaultReadiness(session.knowledge(), context.discovery()).authoritativeVaultReady()) {
            return Status.AUTHORSHIP_NOT_READY;
        }
        if (identity == null) { return Status.DEVICE_IDENTITY_UNAVAILABLE; }
        byte[] binding = CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        try {
            byte[] established = session.establishment().binding().bytes();
            return MessageDigest.isEqual(established, binding) && MessageDigest.isEqual(established, identity.vaultBinding())
                    ? null : Status.DEVICE_IDENTITY_BINDING_MISMATCH;
        } catch (IllegalStateException e) { return Status.DEVICE_IDENTITY_UNAVAILABLE; }
        finally { Arrays.fill(binding, (byte) 0); }
    }
}
