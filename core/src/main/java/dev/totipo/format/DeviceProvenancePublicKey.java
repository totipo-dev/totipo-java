package dev.totipo.format;

import java.security.interfaces.ECPublicKey;

/** Canonical public-key conversion for platform provenance-custody backends. */
public final class DeviceProvenancePublicKey {
    private DeviceProvenancePublicKey() {}

    /**
     * Returns fresh canonical 65-byte uncompressed X9.63 bytes.
     * @param key P-256 public key
     * @return 0x04 || X[32] || Y[32]
     * @throws IllegalArgumentException if parameters or point are not valid P-256
     * @throws NullPointerException if key is null
     */
    public static byte[] encodeX963(ECPublicKey key) { return P256.encode(key); }
}
