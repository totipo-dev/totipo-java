package dev.totipo.format;

import java.util.Collection;

/** Local publication receipts only; never persisted or inferred from remembered routing. */
final class TokenPublicationSuccessGate {
    private TokenPublicationSuccessGate() {}
    static final class VerifiedDeviceAdvertisement {
        private final AcceptedDevice device;
        private final SecurityBytes binding;
        private VerifiedDeviceAdvertisement(AcceptedDevice device, SecurityBytes binding) {
            this.device = device; this.binding = binding;
        }
    }
    static VerifiedDeviceAdvertisement acknowledged(AcceptedDevice device, SecurityBytes binding) {
        if (device.semanticStatus() != SemanticStatus.SUPPORTED_VALID) { throw new IllegalArgumentException("Supported DEVICE required"); }
        return new VerifiedDeviceAdvertisement(device, binding);
    }
    static boolean allows(SnapshotSession session, InitialTokenPublication.Receipt receipt,
                          byte[] localKey, Collection<VerifiedDeviceAdvertisement> evidence) {
        if (receipt == null || !receipt.authorDeviceId().equals(new SecurityBytes(P256.deviceId(localKey), 32))) { return false; }
        return evidence.stream().anyMatch(e -> e != null && e.binding.equals(session.binding())
                && e.device.deviceId().equals(receipt.authorDeviceId())
                && e.device.publicKeyX963().equals(new SecurityBytes(localKey, 65)));
    }
}
