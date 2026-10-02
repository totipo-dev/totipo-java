package org.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Reusable v1 deterministic envelope; no semantic policy or storage. */
final class V1EnvelopeWriter {
    private V1EnvelopeWriter() {}
    record ObjectBytes(ObjectId id, byte[] bytes) {
        ObjectBytes { bytes = bytes.clone(); }
        @Override public byte[] bytes() { return bytes.clone(); }
    }
    static ObjectBytes seal(byte[] root, byte[] semantic) {
        if (semantic.length > EnvelopeReader.SEMANTIC_CAPACITY) {
            throw new IllegalArgumentException("Semantic capacity exceeded");
        }
        byte[] prk = null, idKey = null, objectRoot = null, key = null;
        byte[] padded = new byte[EnvelopeReader.PADDED_BYTES];
        try {
            padded[0] = (byte) (semantic.length >>> 8); padded[1] = (byte) semantic.length;
            System.arraycopy(semantic, 0, padded, 2, semantic.length);
            prk = CryptoSupport.extract(root);
            idKey = CryptoSupport.idKey(prk);
            // Hash the same owned bytes that will be encrypted.
            byte[] exact = Arrays.copyOfRange(padded, 2, 2 + semantic.length);
            ObjectId id;
            try { id = ObjectId.compute(idKey, exact); }
            finally { Arrays.fill(exact, (byte) 0); }
            objectRoot = CryptoSupport.objectRoot(prk);
            key = CryptoSupport.objectKey(objectRoot, id);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(EnvelopeReader.TAG_BYTES * 8, EnvelopeReader.nonce(id)));
            cipher.updateAAD(EnvelopeReader.aad(id));
            return new ObjectBytes(id, cipher.doFinal(padded));
        } catch (GeneralSecurityException e) {
            throw CryptoSupport.unavailable();
        } finally {
            for (byte[] secret : new byte[][]{prk, idKey, objectRoot, key, padded}) {
                if (secret != null) { Arrays.fill(secret, (byte) 0); }
            }
        }
    }
}
