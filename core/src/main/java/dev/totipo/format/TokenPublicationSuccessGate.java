package dev.totipo.format;

import java.util.Arrays;
import java.util.Collection;

/** Derived success eligibility; no persistent success/advertisement flags. */
final class TokenPublicationSuccessGate {
    private TokenPublicationSuccessGate() {}

    /** Reconstructed from exact current bytes under the current vault, never serialized. */
    static final class VerifiedDeviceAdvertisement {
        private final KnownDeviceNode node;
        private final SecurityBytes binding;
        private VerifiedDeviceAdvertisement(KnownDeviceNode node, byte[] root) {
            this.node = node;
            this.binding = new SecurityBytes(CryptoSupport.hmac(root,
                    CryptoSupport.ascii("totipo/v1/local-vault-binding")), 32);
        }
        static VerifiedDeviceAdvertisement read(ObjectId id, byte[] bytes, byte[] root,
                                                 VerificationKeyMaterial material) {
            var opened = EnvelopeReader.open(id.filename(), bytes, root);
            if (opened.status() != EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE) { return null; }
            var assertion = AssertionValidator.validate(opened);
            if (assertion.status() != AssertionValidator.Status.ASSERTION_VALID
                    || assertion.object().plaintext().device() == null
                    || ProvenanceEvaluator.evaluate(assertion.object(), root, material) != ProvenanceStatus.VERIFIED) {
                return null;
            }
            return new VerifiedDeviceAdvertisement(
                    (KnownDeviceNode) AuthenticatedObservation.supported(assertion.object()).record(), root);
        }
    }

    static boolean allows(SecurityMemorySession session, InitialTokenPublication.Receipt receipt,
                          byte[] localKey, Collection<VerifiedDeviceAdvertisement> evidence) {
        if (receipt == null || session.head().status() != SecurityMemoryJournal.Status.CLEAN
                || session.establishment().phase() != LocalEstablishment.Phase.ESTABLISHED
                || session.knowledge().knowledgePersistenceBlocked()
                || session.knowledge().continuity() != LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN
                || !Arrays.equals(P256.deviceId(localKey), receipt.authorDeviceId().bytes())) { return false; }
        var record = session.knowledge().record(receipt.objectId());
        if (!(record instanceof KnownTokenNode token) || token.semanticStatus() != SemanticStatus.SUPPORTED_VALID
                || !token.tokenId().equals(receipt.tokenId()) || !token.authorDeviceId().equals(receipt.authorDeviceId())) {
            return false;
        }
        for (var verified : evidence) {
            if (verified != null && verified.binding.equals(session.establishment().binding())
                    && verified.node.deviceId().equals(receipt.authorDeviceId())
                    && Arrays.equals(verified.node.publicKeyX963().bytes(), localKey)
                    && verified.node.equals(session.knowledge().record(verified.node.objectId()))) { return true; }
        }
        return false;
    }
}
