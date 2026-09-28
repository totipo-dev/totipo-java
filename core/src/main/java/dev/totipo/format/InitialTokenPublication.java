package dev.totipo.format;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;

final class InitialTokenPublication {
    private InitialTokenPublication() {}
    enum Status {
        PUBLISHED_SUCCESS_READY, PUBLISHED_DEVICE_REQUIRED,
        DEVICE_IDENTITY_UNAVAILABLE, DEVICE_IDENTITY_BINDING_MISMATCH, TOKEN_ID_COLLISION, INVALID_VALUE,
        SIGNING_FAILED, LOCAL_VALIDATION_FAILED, PUBLICATION_INCOMPLETE,
        NO_EXISTING_TOKEN, CURRENT_OPAQUE_BLOCKED, CONFIRMATION_REQUIRED_CONFLICT, RESTORATION_INTENT_REQUIRED,
        INVALID_UPDATE_INTENT, FOLD_REQUIRED, CONFIRMATION_PREPARED, CONFIRMATION_NOT_REQUIRED, CONFIRMATION_STALE
    }
    record Receipt(SecurityBytes tokenId, ObjectId objectId, SecurityBytes authorDeviceId) {}
    record Result(Status status, Receipt receipt) {}
    static Result failure(Status status) { return new Result(status, null); }
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
                          EntropySource entropy, Runnable beforePublication) {
        var context = current.get();
        var blocker = gate(context, root, identity);
        if (blocker != null) { return failure(blocker); }
        byte[] id = new byte[32]; entropy.fill(id);
        var tokenId = new SecurityBytes(id, 32);
        if (!context.session().snapshot().topology().currentTokenHeads(tokenId).isEmpty()) {
            return failure(Status.TOKEN_ID_COLLISION);
        }
        return publishValue(root, context.session(), identity, tokenId, value, authorTime, List.of(), store, evidence,
                () -> { beforePublication.run(); return true; });
    }
    static Result publishValue(byte[] root, SnapshotSession session, DeviceIdentityResult identity,
            SecurityBytes tokenId, TokenValue value, byte[] authorTime, List<ObjectId> parents,
            V1ObjectPublicationStore store, Collection<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> evidence,
            java.util.function.BooleanSupplier consentFresh) {
        byte[] exactRoot = root.clone(), time = authorTime.clone();
        byte[] semantic = null;
        try {
            if (exactRoot.length != 32 || time.length != 8) { throw new IllegalArgumentException("Root/time width"); }
            if (value == null) { return failure(Status.INVALID_VALUE); }
            try { TokenWriter.requireCapacity(value, 0); }
            catch (IllegalArgumentException e) { return failure(Status.INVALID_VALUE); }
            try { TokenWriter.requireCapacity(value, parents.size()); }
            catch (IllegalArgumentException e) { return failure(Status.FOLD_REQUIRED); }
            try { semantic = TokenWriter.signed(exactRoot, identity, tokenId.bytes(), value, time, parents); }
            catch (GeneralSecurityException e) { return failure(Status.SIGNING_FAILED); }
            catch (IllegalStateException e) { return failure(Status.LOCAL_VALIDATION_FAILED); }
            var object = V1EnvelopeWriter.seal(exactRoot, semantic);
            var author = new SecurityBytes(identity.deviceId(), 32);
            var node = new AcceptedToken(object.id(), 1, SemanticStatus.SUPPORTED_VALID, tokenId, parents,
                    author, new BigInteger(1, time), value);
            if (!consentFresh.getAsBoolean()) { return failure(Status.CONFIRMATION_STALE); }
            try {
                if (store.publish(object.id(), object.bytes()) == null) { return failure(Status.PUBLICATION_INCOMPLETE); }
            } catch (IOException | RuntimeException e) { return failure(Status.PUBLICATION_INCOMPLETE); }
            session.accept(node);
            var receipt = new Receipt(tokenId, object.id(), author);
            return new Result(TokenPublicationSuccessGate.allows(session, receipt, identity.publicKeyX963(), evidence)
                    ? Status.PUBLISHED_SUCCESS_READY : Status.PUBLISHED_DEVICE_REQUIRED, receipt);
        } finally {
            Arrays.fill(exactRoot, (byte) 0);
            if (semantic != null) { Arrays.fill(semantic, (byte) 0); }
        }
    }
    static Status gate(InitialDeviceAdvertisement.Context context, byte[] root, DeviceIdentityResult identity) {
        if (root.length != 32) { throw new IllegalArgumentException("Root width"); }
        if (identity == null) { return Status.DEVICE_IDENTITY_UNAVAILABLE; }
        byte[] binding = CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        try {
            return MessageDigest.isEqual(binding, context.session().binding().bytes())
                    && MessageDigest.isEqual(binding, identity.vaultBinding()) ? null : Status.DEVICE_IDENTITY_BINDING_MISMATCH;
        } catch (IllegalStateException e) { return Status.DEVICE_IDENTITY_UNAVAILABLE; }
        finally { Arrays.fill(binding, (byte) 0); }
    }
}
