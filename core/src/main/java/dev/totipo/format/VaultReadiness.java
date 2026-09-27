package dev.totipo.format;

import java.util.Objects;

/**
 * Pure §24.2 predicates within an already-established vault continuity epoch,
 * independent of token state. Durable VAULT establishment and local binding under
 * §10 are outer prerequisites, not represented by this type or these predicates.
 * AUTHORITATIVE_VAULT_READY being true does not prove that a newly configured vault
 * has completed durable establishment. Application orchestration must ensure that
 * establishment before invoking this policy for ordinary credential exposure or
 * TOKEN authorship.
 */
final class VaultReadiness {
    private final DurableKnowledgeState knowledge;
    private final DiscoveryState discovery;
    private final boolean activeOpaqueUnscoped;

    VaultReadiness(DurableKnowledgeState knowledge, DiscoveryState discovery) {
        this.knowledge = Objects.requireNonNull(knowledge);
        this.discovery = Objects.requireNonNull(discovery);
        // M2 has neither reclassification nor reset: every retained unscoped record
        // belongs to this epoch and remains active, including after remote disappearance.
        activeOpaqueUnscoped = knowledge.records().values().stream()
                .anyMatch(OpaqueUnscopedRecord.class::isInstance);
    }

    DurableKnowledgeState knowledge() { return knowledge; }
    DiscoveryState discovery() { return discovery; }
    boolean activeOpaqueUnscoped() { return activeOpaqueUnscoped; }
    boolean baseOperationSafe() {
        return knowledge.continuity() == LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN
                && !knowledge.knowledgePersistenceBlocked();
    }
    boolean authoritativeVaultReady() {
        return baseOperationSafe() && discovery == DiscoveryState.READY && !activeOpaqueUnscoped;
    }
    boolean candidateUseReady() { return baseOperationSafe(); }
}
