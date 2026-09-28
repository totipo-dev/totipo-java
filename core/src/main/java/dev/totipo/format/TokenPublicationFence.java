package dev.totipo.format;

/** Process-local, session-wide TOKEN-update linearization state. No value/bytes retained. */
final class TokenPublicationFence {
    private boolean reconciliationRequired;
    private long epoch;

    boolean reconciliationRequired() { return reconciliationRequired; }
    long epoch() { return epoch; }

    void publicationUnacknowledged() {
        reconciliationRequired = true;
        epoch = Math.incrementExact(epoch);
    }

    /**
     * Serialized owner recovery entry point, not a reset or caller-supplied scan receipt.
     * Runs a new normal authenticated discovery pass on this exact session, including
     * durable insertion and graph recomputation. Failed/incomplete/blocked discovery
     * leaves the fence raised. The local epoch invalidates old consent even when the
     * reconciled graph is unchanged; the owner still advances its discovery revision.
     */
    DiscoveryResult reconcile(DiscoverySource source, byte[] root, SecurityMemorySession session) {
        if (session.tokenPublicationFence() != this) {
            throw new IllegalArgumentException("Publication fence session mismatch");
        }
        byte[] binding = CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        try {
            if (root.length != 32 || session.establishment().phase() != LocalEstablishment.Phase.ESTABLISHED
                    || !java.security.MessageDigest.isEqual(binding, session.establishment().binding().bytes())) {
                throw new IllegalArgumentException("Reconciliation vault binding mismatch");
            }
        } finally { java.util.Arrays.fill(binding, (byte) 0); }
        epoch = Math.incrementExact(epoch);
        var result = DiscoveryCoordinator.discover(source, root, session);
        if (result.resourceComplete() && result.discoveryState() == DiscoveryState.READY
                && session.head().status() == SecurityMemoryJournal.Status.CLEAN
                && new VaultReadiness(session.knowledge(), result.discoveryState()).authoritativeVaultReady()) {
            reconciliationRequired = false;
        }
        return result;
    }
}
