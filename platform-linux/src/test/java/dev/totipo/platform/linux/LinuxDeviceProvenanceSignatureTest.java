package dev.totipo.platform.linux;

import dev.totipo.format.DeviceProvenanceKey;
import dev.totipo.format.DeviceProvenanceSignature;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LinuxDeviceProvenanceSignatureTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path root;
    static byte[] hex(String value) { return HexFormat.of().parseHex(value); }

    @Test void malformedProviderOutputNeverEscapesRawSpiAndDoesNotCloseHandle() throws Exception {
        byte[][] output = {null}; int[] calls = {0};
        try (DeviceProvenanceKey key = new LinuxDeviceProvenanceKey(new byte[32], new byte[65], null,
                (privateKey, message) -> { calls[0]++; return output[0]; })) {
            assertThrows(NullPointerException.class, () -> key.signSha256Ecdsa(null)); assertEquals(0, calls[0]);
            for (byte[] bad : new byte[][]{
                    null, new byte[0], new byte[73], new byte[8],
                    hex("3003020101"), // only one INTEGER
                    hex("300602010102010100"), // trailing byte
                    hex("300702020001020101"), // nonminimal INTEGER (existing core fixture)
                    hex("3006020180020101"), // negative INTEGER (existing core fixture)
                    hex("3006020101020180"), // negative s
                    hex("308106020101020101") // nonminimal sequence length
            }) {
                output[0] = bad;
                if (bad != null) assertThrows(GeneralSecurityException.class,
                        () -> DeviceProvenanceSignature.validateCanonicalDer(bad));
                assertThrows(GeneralSecurityException.class, () -> key.signSha256Ecdsa(new byte[]{1}));
                output[0] = hex("3006020101020101");
                assertArrayEquals(output[0], key.signSha256Ecdsa(new byte[]{1})); // Raw handle remains open.
            }
        }
    }
    @Test void canonicalHighSIsReturnedUnchangedInFreshCallerOwnedArrays() throws Exception {
        // r=1, s=P-256 order-1: structural check deliberately does not verify mathematics.
        byte[] highS = hex("3026020101022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
        byte[] original = highS.clone(), message = {1, 2, 3};
        DeviceProvenanceSignature.validateCanonicalDer(highS);
        try (DeviceProvenanceKey key = new LinuxDeviceProvenanceKey(new byte[32], new byte[65], null,
                (privateKey, supplied) -> { assertArrayEquals(message, supplied); return highS; })) {
            byte[] a = key.signSha256Ecdsa(message), b = key.signSha256Ecdsa(message);
            assertArrayEquals(original, a); assertArrayEquals(original, b);
            assertNotSame(highS, a); assertNotSame(a, b);
            a[0] = 0; Arrays.fill(highS, (byte) 0);
            assertArrayEquals(original, b); DeviceProvenanceSignature.validateCanonicalDer(b);
        }
    }
    @Test void realProviderRawSignaturesAreCanonicalVerifyAndLeaveCustodyUnchanged() throws Exception {
        try (var store = LinuxDeviceProvenanceKeyStore.open(root); DeviceProvenanceKey key = store.createDurably(new byte[32])) {
            Path file = root.resolve("device-provenance-v1.bin");
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file));
            byte[] publicBytes = key.publicKeyX963();
            var parameters = AlgorithmParameters.getInstance("EC"); parameters.init(new ECGenParameterSpec("secp256r1"));
            var publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(
                    new BigInteger(1, Arrays.copyOfRange(publicBytes, 1, 33)),
                    new BigInteger(1, Arrays.copyOfRange(publicBytes, 33, 65))), parameters.getParameterSpec(ECParameterSpec.class)));
            for (int i = 0; i < 32; i++) {
                byte[] message = {(byte) i};
                byte[] signature = key.signSha256Ecdsa(message);
                assertTrue(signature.length > 0 && signature.length <= 72);
                DeviceProvenanceSignature.validateCanonicalDer(signature);
                var verifier = Signature.getInstance("SHA256withECDSA"); verifier.initVerify(publicKey); verifier.update(message);
                assertTrue(verifier.verify(signature)); assertArrayEquals(new byte[]{(byte) i}, message);
            }
            assertArrayEquals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
        }
    }
}
