package dev.totipo.format;

import java.io.IOException;

/** Authenticate external current DEVICE bytes and obtain a new local publication receipt.
 * Used when reusing an advertisement after restart; no persisted advertised flag exists. */
final class DeviceAdvertisementReader {
    private DeviceAdvertisementReader() {}
    static TokenPublicationSuccessGate.VerifiedDeviceAdvertisement acknowledge(
            ObjectId id, byte[] bytes, byte[] root, V1ObjectPublicationStore store) throws IOException {
        byte[] exact = bytes.clone();
        var opened = EnvelopeReader.open(id.filename(), exact, root);
        if (opened.status() != EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE) { return null; }
        var assertion = AssertionValidator.validate(opened);
        if (assertion.status() != AssertionValidator.Status.ASSERTION_VALID
                || assertion.object().plaintext().device() == null
                || ProvenanceEvaluator.evaluate(assertion.object(), root, VerificationKeyMaterial.keys()) != ProvenanceStatus.VERIFIED) {
            return null;
        }
        if (store.publish(id, exact) == null) { return null; }
        return TokenPublicationSuccessGate.acknowledged((AcceptedDevice) AuthenticatedObservation.supported(assertion.object()).record(),
                new SecurityBytes(CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding")), 32));
    }
}
