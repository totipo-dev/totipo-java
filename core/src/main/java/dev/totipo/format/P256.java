package dev.totipo.format;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/** §16/§19 primitives only. No author lookup, provenance status or device admission. */
final class P256 {
    private P256() {}

    static ECPublicKey decode(byte[] protocolKey) {
        if (protocolKey.length != 65 || protocolKey[0] != 4) {
            throw new IllegalArgumentException("Invalid P-256 public key representation");
        }
        try {
            var parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            var spec = parameters.getParameterSpec(ECParameterSpec.class);
            var x = new BigInteger(1, Arrays.copyOfRange(protocolKey, 1, 33));
            var y = new BigInteger(1, Arrays.copyOfRange(protocolKey, 33, 65));
            var curve = spec.getCurve();
            var p = ((ECFieldFp) curve.getField()).getP();
            // KeyFactory alone is not a portable guarantee of point validation.
            if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0
                    || !y.multiply(y).mod(p).equals(x.multiply(x).multiply(x)
                            .add(curve.getA().multiply(x)).add(curve.getB()).mod(p))) {
                throw new IllegalArgumentException("Invalid P-256 public point");
            }
            return (ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
        } catch (GeneralSecurityException e) {
            throw CryptoSupport.unavailable();
        }
    }

    /** Identity covers the exact structural protocol bytes, independently of point validity (§21). */
    static byte[] deviceId(byte[] protocolKey) {
        if (protocolKey.length != 65) {
            throw new IllegalArgumentException("Device public key must be 65 bytes");
        }
        return CryptoSupport.sha256(CryptoSupport.ascii("totipo/v1/device-id"), protocolKey);
    }

    /** Caller supplies canonical unsigned bytes, omitting the entire final SIGNATURE TLV. */
    static byte[] signatureInput(byte[] root, int objectType, byte[] unsignedSemantic) {
        if (objectType != 1 && objectType != 2) {
            throw new IllegalArgumentException("Unsupported signature object type");
        }
        byte[] prk = CryptoSupport.extract(root);
        byte[] context = null;
        try {
            context = CryptoSupport.signatureContext(prk);
            return CryptoSupport.join(CryptoSupport.ascii(objectType == 1
                    ? "totipo/v1/token" : "totipo/v1/device"), context, unsignedSemantic);
        } finally {
            Arrays.fill(prk, (byte) 0);
            if (context != null) {
                Arrays.fill(context, (byte) 0);
            }
        }
    }

    /** Normal verification keeps root-derived signature input operation-local. */
    static boolean verifySemantic(byte[] root, int objectType, byte[] unsignedSemantic,
                                  byte[] key, byte[] signature) {
        byte[] input = signatureInput(root, objectType, unsignedSemantic);
        try {
            return verify(key, input, signature);
        } finally {
            Arrays.fill(input, (byte) 0);
        }
    }

    /** Mathematical primitive; protocol callers independently enforce canonical DER. */
    static boolean verify(byte[] protocolKey, byte[] message, byte[] signature) {
        if (signature.length == 0 || signature.length > 72) {
            return false;
        }
        ECPublicKey key;
        try {
            key = decode(protocolKey);
        } catch (IllegalArgumentException e) {
            return false;
        }
        try {
            var verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(key);
            verifier.update(message);
            try {
                return verifier.verify(signature);
            } catch (SignatureException e) {
                // Invalid supplied signature values/encoding, not a local resource failure.
                return false;
            }
        } catch (GeneralSecurityException e) {
            // Setup/update failures occurred before examining the supplied signature.
            throw CryptoSupport.unavailable();
        }
    }
}
