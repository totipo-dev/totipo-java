package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class EcdsaDerSignatureTest {
    @TestFactory
    List<DynamicTest> rejectsMalformedDerIndependentlyOfJca() {
        return List.of(
                "3106020101020101", // SEQUENCE tag
                "3006030101020101", // r tag
                "3006020101030101", // s tag
                "30", "3081", // truncated lengths
                "3007020101020101", // sequence mismatch
                "3006020801020101", // INTEGER mismatch
                "300602010102010100", // trailing byte
                "30050200020101", "30050201010200", // empty r/s
                "3006020180020101", "3006020101020180", // negative / omitted sign protection
                "300702020001020101", // redundant zero
                "308106020101020101", // unnecessary long-form SEQUENCE
                "300702810101020101", // unnecessary long-form INTEGER
                "30800201010201010000", // indefinite
                "3009020101020101020101" // third INTEGER
        ).stream().map(hex -> DynamicTest.dynamicTest(hex, () ->
                {
                    byte[] bytes = ProvenanceTest.hex(hex);
                    assertFalse(EcdsaDerSignature.isCanonical(bytes));
                    assertThrows(java.security.GeneralSecurityException.class,
                            () -> DeviceProvenanceSignature.validateCanonicalDer(bytes));
                })).toList();
    }

    @Test
    void canonicalEncodingIsSeparateFromMathematicsAndAllowsAllScalarWidths() {
        assertTrue(EcdsaDerSignature.isCanonical(ProvenanceTest.hex("3006020100020100")));
        assertDoesNotThrow(() -> DeviceProvenanceSignature.validateCanonicalDer(ProvenanceTest.hex("3006020100020100")));
        assertTrue(EcdsaDerSignature.isCanonical(ProvenanceTest.hex("300702020080020101")));
        for (int r = 1; r <= 33; r++) {
            for (int s = 1; s <= 33; s++) {
                byte[] der = new byte[6 + r + s];
                der[0] = 0x30; der[1] = (byte) (der.length - 2); der[2] = 2; der[3] = (byte) r;
                der[4] = 1; der[4 + r] = 2; der[5 + r] = (byte) s; der[6 + r] = 1;
                if (r == 33) { der[4] = 0; der[5] = (byte) 0x80; }
                if (s == 33) { der[6 + r] = 0; der[7 + r] = (byte) 0x80; }
                assertTrue(EcdsaDerSignature.isCanonical(der), "r=" + r + ", s=" + s);
                byte[] before = der.clone();
                assertDoesNotThrow(() -> DeviceProvenanceSignature.validateCanonicalDer(der));
                assertArrayEquals(before, der);
            }
        }
        assertFalse(EcdsaDerSignature.isCanonical(new byte[73]));
    }
    @Test void publicBridgeRejectsNullAndBoundsDeterministically() {
        assertThrows(NullPointerException.class, () -> DeviceProvenanceSignature.validateCanonicalDer(null));
        for (int length : new int[]{0, 73}) assertThrows(java.security.GeneralSecurityException.class,
                () -> DeviceProvenanceSignature.validateCanonicalDer(new byte[length]));
    }
}
