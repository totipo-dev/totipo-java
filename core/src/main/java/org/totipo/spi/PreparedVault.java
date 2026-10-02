package org.totipo.spi;

/** Owns one noncanonical representation. Read-back freshly observes that representation;
 * both mutations use that same representation, never reconstruct from the input array.
 * Exactly one canonical mutation attempt is allowed; repeated use is a lifecycle error.
 * Close abandons/cleans staging best-effort and never changes canonical vault.
 * Replacement requires neither atomic move nor CAS; core owns stale comparison. */
public interface PreparedVault extends AutoCloseable {
    BoundedRead readBack(int expectedBytes);
    VaultInstall installCanonicalIfAbsent();
    VaultReplace replaceCanonical();
    @Override void close();
}
