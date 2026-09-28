package dev.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Objects;

/** Encoding validation for Totipo v1 P-256 ECDSA provenance signatures. */
public final class DeviceProvenanceSignature {
    private DeviceProvenanceSignature() {}

    /**
     * Validates the nonempty, at-most-72-byte canonical DER encoding accepted by
     * Totipo v1. Structural validation only: does not check scalar ranges or verify
     * a public key, normalize S, modify input, or retain caller bytes.
     * @param signature exact DER signature bytes
     * @throws NullPointerException if signature is null
     * @throws GeneralSecurityException if the encoding is not accepted
     */
    public static void validateCanonicalDer(byte[] signature) throws GeneralSecurityException {
        Objects.requireNonNull(signature);
        if (!EcdsaDerSignature.isCanonical(signature))
            throw new GeneralSecurityException("INVALID_PROVENANCE_SIGNATURE_ENCODING");
    }
}
