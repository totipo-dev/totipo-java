package dev.totipo.format;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Thread-confined synchronous initial-only lifecycle. The owner must serialize local
 * state/discovery changes with this operation and publication; store callbacks must not
 * reenter that owner. Snapshot revision must advance on every discovery/configuration
 * change (including changes that return to READY). No scan or global completeness claim.
 * Hidden remote history can later be concurrent with this parentless advertisement.
 */
final class InitialDeviceAdvertisement {
    private InitialDeviceAdvertisement() {}
    enum Status {
        PUBLISHED_AND_REMEMBERED, AUTHORSHIP_NOT_READY, LOCAL_STATE_NOT_ESTABLISHED,
        DEVICE_IDENTITY_UNAVAILABLE, DEVICE_IDENTITY_BINDING_MISMATCH, DEVICE_FRONTIER_NOT_EMPTY,
        INVALID_DISPLAY_NAME, CAPACITY_EXCEEDED, SIGNING_FAILED, LOCAL_VALIDATION_FAILED,
        PUBLICATION_INCOMPLETE, KNOWLEDGE_PERSISTENCE_FAILED, OPERATION_STALE
    }
    record Context(SecurityMemorySession session, DiscoveryState discovery, long revision) {
        Context { Objects.requireNonNull(session); Objects.requireNonNull(discovery); }
    }
    record Result(Status status, ObjectId objectId, SecurityBytes deviceId,
                  V1ObjectPublicationStore.PublicationResult publication) {}
    private static Result failure(Status status) { return new Result(status, null, null, null); }

    static Result publish(byte[] root, Supplier<Context> current, DeviceIdentityResult identity,
                          String name, byte[] authorTime, V1ObjectPublicationStore store) {
        return publish(root, current, identity, name, authorTime, store, () -> {});
    }

    /** Deterministic test/owner seam after validation, before the final freshness check. */
    static Result publish(byte[] root, Supplier<Context> current, DeviceIdentityResult identity,
                          String name, byte[] authorTime, V1ObjectPublicationStore store,
                          Runnable beforeRecheck) {
        Objects.requireNonNull(current); Objects.requireNonNull(store); Objects.requireNonNull(beforeRecheck);
        byte[] exactRoot = root.clone(), time = authorTime.clone();
        if (exactRoot.length != 32 || time.length != 8) {
            Arrays.fill(exactRoot, (byte) 0);
            throw new IllegalArgumentException("Root/AUTHOR_TIME width");
        }
        try {
            Context start = current.get();
            Status blocker = gate(start, exactRoot, identity);
            if (blocker != null) { return failure(blocker); }
            byte[] display;
            try { display = DeviceWriter.displayName(name); }
            catch (IllegalArgumentException e) { return failure(Status.INVALID_DISPLAY_NAME); }
            try { DeviceWriter.requireCapacity(display.length, 0); }
            catch (IllegalArgumentException e) { return failure(Status.CAPACITY_EXCEEDED); }
            var session = start.session();
            var head = session.head();
            var knowledge = session.knowledge();
            byte[] key = identity.publicKeyX963();
            byte[] semantic;
            try { semantic = DeviceWriter.signed(exactRoot, identity, display, time, List.of()); }
            catch (GeneralSecurityException e) { return failure(Status.SIGNING_FAILED); }
            catch (IllegalStateException e) { return failure(Status.LOCAL_VALIDATION_FAILED); }
            V1EnvelopeWriter.ObjectBytes object;
            AuthenticatedObservation observation;
            try {
                object = V1EnvelopeWriter.seal(exactRoot, semantic);
                var opened = EnvelopeReader.open(object.id().filename(), object.bytes(), exactRoot);
                if (opened.status() != EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE
                        || !Arrays.equals(semantic, opened.semanticBytes())
                        || !DeviceWriter.matches(opened.plaintext(), key, display, time, List.of())) {
                    return failure(Status.LOCAL_VALIDATION_FAILED);
                }
                var assertion = AssertionValidator.validate(opened);
                if (assertion.status() != AssertionValidator.Status.ASSERTION_VALID
                        || ProvenanceEvaluator.evaluate(assertion.object(), exactRoot,
                        VerificationKeyMaterial.available(List.of())) != ProvenanceStatus.VERIFIED) {
                    return failure(Status.LOCAL_VALIDATION_FAILED);
                }
                observation = AuthenticatedObservation.supported(assertion.object());
            } catch (IllegalStateException e) { return failure(Status.LOCAL_VALIDATION_FAILED); }
            beforeRecheck.run();
            Context now = current.get();
            if (now.session() != session || now.revision() != start.revision()
                    || now.discovery() != start.discovery() || session.head() != head
                    || session.knowledge() != knowledge || gate(now, exactRoot, identity) != null) {
                return failure(Status.OPERATION_STALE);
            }
            V1ObjectPublicationStore.PublicationResult published;
            try {
                published = store.publishDurably(object.id(), object.bytes());
                if (published == null) { return failure(Status.PUBLICATION_INCOMPLETE); }
            } catch (IOException e) { return failure(Status.PUBLICATION_INCOMPLETE); }
            var update = session.commit(observation);
            if (update.outcome() != DurableKnowledgeState.Outcome.INSERTED
                    && update.outcome() != DurableKnowledgeState.Outcome.UNCHANGED) {
                return failure(Status.KNOWLEDGE_PERSISTENCE_FAILED);
            }
            return new Result(Status.PUBLISHED_AND_REMEMBERED, object.id(),
                    new SecurityBytes(P256.deviceId(key), 32), published);
        } finally { Arrays.fill(exactRoot, (byte) 0); }
    }

    private static Status gate(Context context, byte[] root, DeviceIdentityResult identity) {
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
            if (!MessageDigest.isEqual(established, binding)
                    || !MessageDigest.isEqual(established, identity.vaultBinding())) {
                return Status.DEVICE_IDENTITY_BINDING_MISMATCH;
            }
            if (!new GraphTopology(session.knowledge()).currentDeviceHeads(
                    new SecurityBytes(identity.deviceId(), 32)).isEmpty()) {
                return Status.DEVICE_FRONTIER_NOT_EMPTY;
            }
            return null;
        } catch (IllegalStateException e) { return Status.DEVICE_IDENTITY_UNAVAILABLE; }
        finally { Arrays.fill(binding, (byte) 0); }
    }
}
