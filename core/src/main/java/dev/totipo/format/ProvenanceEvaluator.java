package dev.totipo.format;

import java.security.ProviderException;
import java.util.Arrays;
import dev.totipo.format.AssertionValidator.AssertionValidObject;

/** Pure, repeatable §16.1/§21.2 evaluation under the current unlocked vault root. */
final class ProvenanceEvaluator {
    private ProvenanceEvaluator() {}

    /** Reevaluate currently readable known assertions when local key material arrives.
     * Returns only attribution, in input order; never mutates assertions or accepted state.
     * Caller supplies the current established vault's root and existing candidate material.
     * Unreadable assertions must be evaluated when their exact bytes become available. */
    static java.util.List<ProvenanceStatus> withLocalIdentity(
            java.util.List<AssertionValidObject> readable, byte[] vaultRoot,
            VerificationKeyMaterial material, DeviceIdentityResult local) {
        if (vaultRoot.length != 32) { throw new IllegalArgumentException("Root key must be 32 bytes"); }
        byte[] binding = CryptoSupport.hmac(vaultRoot, CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        if (!java.security.MessageDigest.isEqual(binding, local.vaultBinding())) {
            throw new IllegalArgumentException("Local identity belongs to another vault");
        }
        var candidates = new java.util.ArrayList<>(material.candidates());
        candidates.add(local.verificationCandidate());
        var combined = VerificationKeyMaterial.available(candidates);
        return readable.stream().map(a -> evaluate(a, vaultRoot, combined)).toList();
    }

    static ProvenanceStatus evaluate(AssertionValidObject assertion, byte[] vaultRoot,
                                     VerificationKeyMaterial material) {
        if (vaultRoot.length != 32) { throw new IllegalArgumentException("Root key must be 32 bytes"); }
        if (material.isTemporarilyUnavailable()) { return ProvenanceStatus.UNRESOLVED; }
        var value = assertion.plaintext();
        // §44's explicit no-valid-signature representation needs no candidate lookup.
        if (value.signature().length == 0) { return ProvenanceStatus.REJECTED; }
        byte[] unsigned = null;
        try {
            byte[] key = value.device() == null ? tokenKey(value.routing().authorDeviceId(), material)
                    : value.device().publicKey();
            if (key == null) { return ProvenanceStatus.UNRESOLVED; }
            if (key.length == 0) { return ProvenanceStatus.REJECTED; }
            byte[] signature = value.signature();
            if (!EcdsaDerSignature.isCanonical(signature)) { return ProvenanceStatus.REJECTED; }
            unsigned = assertion.unsignedSemantic();
            return P256.verifySemantic(vaultRoot, value.routing().objectType(), unsigned, key, signature)
                    ? ProvenanceStatus.VERIFIED : ProvenanceStatus.REJECTED;
        } catch (IllegalStateException | ProviderException e) {
            return ProvenanceStatus.UNRESOLVED;
        } finally {
            if (unsigned != null) { Arrays.fill(unsigned, (byte) 0); }
        }
    }

    private static byte[] tokenKey(byte[] author, VerificationKeyMaterial material) {
        byte[] matching = null;
        for (var candidate : material.candidates()) {
            byte[] key = candidate.publicKey();
            // Caller identity labels establish neither eligibility nor a collision.
            if (!Arrays.equals(author, P256.deviceId(key))) { continue; }
            if (matching != null && !Arrays.equals(matching, key)) {
                return new byte[0]; // Distinct bytes for one actual derived identity: never choose.
            }
            matching = key;
        }
        return matching;
    }
}
