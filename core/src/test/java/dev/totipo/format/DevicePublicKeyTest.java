package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class DevicePublicKeyTest {
    @Test void fixedVectorsPadBothCoordinatesAndStripOnlySignOctet() {
        // Fixed implementation-local JCA-generated public fixtures, not runtime expected values.
        String[][] vectors = {
            {"04e058ee7b4962a740f9173eab25a8cf2dfd35d04239abf2b43b4289a882da3c9f"
                    + "006f477eeb6d36b48fdb5888730fd4000308888277f2e156f746d16dae3e2557",
             "9d59228de3c3659f7125efa6b4214a95c9dfbe410f630a65a805ac85c1fd9824"},
            {"040066674bbe388ef6cdc38d56c933defbde3746f8df4a89b3a5f0170f0fc3a148f"
                    + "5b0f7bdc490537058a0a47e4ad330c5d30fd6d8b0213adef3742ae21237520a",
             "fca6dec176be3a785e6c7e348d6aaa53a4bdd4820c0b53935b88ab63efa18374"}
        };
        for (var vector : vectors) {
            byte[] expected = HexFormat.of().parseHex(vector[0]);
            assertEquals(65, expected.length);
            var decoded = P256.decode(expected);
            assertTrue(decoded.getW().getAffineX().toByteArray().length < 32
                    || decoded.getW().getAffineY().toByteArray().length < 32);
            assertArrayEquals(expected, P256.encode(decoded));
            assertArrayEquals(P256.encode(decoded), DeviceProvenancePublicKey.encodeX963(decoded));
            assertArrayEquals(HexFormat.of().parseHex(vector[1]), P256.deviceId(expected));
        }
    }
    @Test void wrongCurveAndMalformedCoordinatesRejectedWithoutTruncation() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        var other = (ECPublicKey) generator.generateKeyPair().getPublic();
        assertThrows(IllegalArgumentException.class, () -> P256.encode(other));
        assertThrows(IllegalArgumentException.class, () -> DeviceProvenancePublicKey.encodeX963(other));
        var good = (ECPublicKey) FakeDeviceKeyStore.generate().getPublic();
        for (var point : new ECPoint[]{ECPoint.POINT_INFINITY, new ECPoint(BigInteger.valueOf(-1), BigInteger.ONE),
                new ECPoint(BigInteger.ONE.shiftLeft(256), BigInteger.ONE),
                new ECPoint(BigInteger.ZERO, BigInteger.ZERO)}) {
            assertThrows(IllegalArgumentException.class, () -> P256.encode(key(point, good.getParams())));
        }
        var p = good.getParams();
        var wrongOrder = new ECParameterSpec(p.getCurve(), p.getGenerator(), p.getOrder().subtract(BigInteger.ONE), p.getCofactor());
        assertThrows(IllegalArgumentException.class, () -> P256.encode(key(good.getW(), wrongOrder)));
        assertThrows(IllegalArgumentException.class, () -> P256.encode(key(good.getW(), null)));
        assertThrows(NullPointerException.class, () -> P256.encode(null));
        assertThrows(NullPointerException.class, () -> P256.decode(null));
        assertThrows(NullPointerException.class, () -> P256.deviceId(null));
    }
    private static ECPublicKey key(ECPoint point, ECParameterSpec parameters) {
        return new ECPublicKey() {
            @Override public ECPoint getW() { return point; }
            @Override public ECParameterSpec getParams() { return parameters; }
            @Override public String getAlgorithm() { return "EC"; }
            @Override public String getFormat() { throw new AssertionError("No encoding required"); }
            @Override public byte[] getEncoded() { throw new AssertionError("No encoding required"); }
        };
    }
}
