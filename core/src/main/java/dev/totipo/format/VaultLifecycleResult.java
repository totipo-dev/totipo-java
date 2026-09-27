package dev.totipo.format;

import java.util.Arrays;

/** Scoped established secret plus immutable discovery snapshot; no live persistence handle.
 * Caller closes the secret. No password is retained. Thread-confined. */
final class VaultLifecycleResult implements AutoCloseable {
    enum Status {
        CREATED_ESTABLISHED, CREATED_ESTABLISHED_DISCOVERY_INCOMPLETE,
        OPENED_ESTABLISHED, OPENED_ESTABLISHED_DISCOVERY_INCOMPLETE,
        AUTHENTICATION_FAILED, INVALID_BOOTSTRAP, INVALID_PASSWORD_INPUT,
        CANONICAL_VAULT_ABSENT, CANONICAL_VAULT_PRESENT, BOOTSTRAP_STORAGE_UNAVAILABLE,
        CREATE_BLOCKED_EXISTING_OBJECT_CANDIDATES, CREATE_BLOCKED_DISCOVERY_INCOMPLETE,
        LOCAL_STATE_NOT_FRESH, LOCAL_SECURITY_MEMORY_MISSING, LOCAL_SECURITY_MEMORY_INVALID,
        LOCAL_TAIL_REPAIR_REQUIRED, PENDING_CANONICAL_ABSENT, PENDING_BINDING_MISMATCH,
        ESTABLISHED_BINDING_MISMATCH, PUBLICATION_INCOMPLETE, LOCAL_PERSISTENCE_FAILURE,
        CRYPTO_CONSTRUCTION_FAILED
    }
    private final Status status;
    private final byte[] root;
    private final DiscoveryResult discovery;
    private boolean closed;

    private VaultLifecycleResult(Status status, byte[] root, DiscoveryResult discovery) {
        this.status = status;
        this.root = root == null ? null : root.clone();
        this.discovery = discovery;
    }
    static VaultLifecycleResult failure(Status status) { return new VaultLifecycleResult(status, null, null); }
    static VaultLifecycleResult established(boolean created, byte[] root, DiscoveryResult discovery) {
        boolean incomplete = discovery.discoveryState() == DiscoveryState.PROCESSING_INCOMPLETE;
        return new VaultLifecycleResult(created
                ? incomplete ? Status.CREATED_ESTABLISHED_DISCOVERY_INCOMPLETE : Status.CREATED_ESTABLISHED
                : incomplete ? Status.OPENED_ESTABLISHED_DISCOVERY_INCOMPLETE : Status.OPENED_ESTABLISHED,
                root, discovery);
    }
    Status status() { return status; }
    DiscoveryResult discovery() { return discovery; }
    byte[] root() {
        if (closed) { throw new IllegalStateException("Lifecycle result closed"); }
        return root == null ? null : root.clone();
    }
    @Override public void close() {
        if (root != null) { Arrays.fill(root, (byte) 0); }
        closed = true;
    }
    @Override public String toString() { return "VaultLifecycleResult[" + status + "]"; }
}
