package org.totipo.format;

import org.totipo.conformance.VectorCaseLoader;
import java.io.IOException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Opaque r16 bytes for primitive tests; no TOKEN grammar or semantic verdict is asserted. */
final class EnvelopeTestBytes {
    private EnvelopeTestBytes() {}

    static VectorCaseLoader.Case fixture() throws IOException {
        return VectorCaseLoader.cryptoCases().stream()
                .filter(c -> c.id().equals("v1.crypto.token-root.001")).findFirst().orElseThrow();
    }

    static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws Exception {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }
}
