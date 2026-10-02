package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Isolated;

@Isolated("Temporarily changes the default locale")
class TotpTest {
    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
    private static final BigInteger U64_LIMIT = BigInteger.ONE.shiftLeft(64);

    private static TokenValue.Credential credential(int algorithm, int digits, long period) {
        return new TokenValue.Credential(algorithm, digits, period, new SecurityBytes(SECRET, SECRET.length));
    }

    @Test
    void periodTransitionsUseFloorIncludingLargeUnsignedPeriods() {
        for (long p : new long[]{1, 17, 30, 1L << 31, 0xffff_ffffL}) {
            long[] times = {0, p - 1, p, 2 * p - 1, 2 * p};
            int[] counters = {0, 0, 1, 1, 2};
            // RFC 4226 Appendix D, the same public SHA-1 key, six digits.
            String[] codes = {"755224", "287082", "359152"};
            for (int i = 0; i < times.length; i++) {
                assertEquals(BigInteger.valueOf(counters[i]),
                        Totp.timeStep(BigInteger.valueOf(times[i]), p));
                assertEquals(codes[counters[i]], Totp.generate(credential(1, 6, p), times[i]));
            }
        }
    }

    @Test
    void exactUnsignedCounterEncodingsAndFullDomainCalculations() throws Exception {
        String[] encodings = {"0000000000000000", "0000000000000001", "0000000080000000",
                "00000000ffffffff", "0000000100000000", "7fffffffffffffff",
                "8000000000000000", "ffffffffffffffff"};
        for (String encoding : encodings) {
            BigInteger counter = new BigInteger(encoding, 16);
            byte[] bytes = HexFormat.of().parseHex(encoding);
            assertArrayEquals(bytes, Totp.encodeCounter(counter));
            for (int algorithm = 1; algorithm <= 3; algorithm++) {
                String name = new String[]{"HmacSHA1", "HmacSHA256", "HmacSHA512"}[algorithm - 1];
                // Independent test oracle: literal wire counter, unsigned integer slice,
                // explicit modulus and string padding; no production helpers reused.
                Mac mac = Mac.getInstance(name);
                mac.init(new SecretKeySpec(SECRET, name));
                byte[] digest = mac.doFinal(bytes);
                int offset = Byte.toUnsignedInt(digest[digest.length - 1]) % 16;
                BigInteger binary = new BigInteger(1, Arrays.copyOfRange(digest, offset, offset + 4))
                        .and(BigInteger.valueOf(0x7fff_ffff));
                for (int digits = 6; digits <= 8; digits++) {
                    String decimal = binary.mod(BigInteger.TEN.pow(digits)).toString();
                    String expected = "0".repeat(digits - decimal.length()) + decimal;
                    for (long p : new long[]{1, 17, 0xffff_ffffL}) {
                        BigInteger time = counter.multiply(BigInteger.valueOf(p));
                        assertEquals(expected, Totp.generate(credential(algorithm, digits, p), time));
                        assertEquals(expected, Totp.generate(credential(algorithm, digits, p),
                                time.add(BigInteger.valueOf(p - 1))));
                    }
                }
            }
        }
        assertEquals(Totp.generate(credential(1, 8, 1), BigInteger.valueOf(Long.MAX_VALUE)),
                Totp.generate(credential(1, 8, 1), Long.MAX_VALUE));
    }

    @Test
    void rejectsNegativeTimeAndCounterOverflowBeforeHmac() {
        var c = credential(1, 6, 1);
        assertThrows(IllegalArgumentException.class, () -> Totp.generate(c, -1));
        assertThrows(IllegalArgumentException.class, () -> Totp.generate(c, Long.MIN_VALUE));
        assertThrows(IllegalArgumentException.class, () -> Totp.generate(c, BigInteger.ONE.negate()));
        assertThrows(IllegalArgumentException.class, () -> Totp.encodeCounter(BigInteger.ONE.negate()));
        assertThrows(IllegalArgumentException.class, () -> Totp.encodeCounter(U64_LIMIT));
        for (long p : new long[]{1, 30, 0xffff_ffffL}) {
            var withPeriod = credential(1, 6, p);
            assertThrows(IllegalArgumentException.class,
                    () -> Totp.generate(withPeriod, U64_LIMIT.multiply(BigInteger.valueOf(p))));
        }
    }

    @Test
    void directDynamicTruncationAtBothOffsetExtremes() {
        for (int length : new int[]{20, 32, 64}) {
            for (int offset : new int[]{0, 15}) {
                for (int value : new int[]{0, 0x0080fffe, 0x7fff_fffe, 0x7fff_ffff}) {
                    byte[] digest = new byte[length];
                    digest[length - 1] = (byte) (0xf0 | offset);
                    digest[offset] = (byte) ((value >>> 24) | 0x80);
                    digest[offset + 1] = (byte) (value >>> 16);
                    digest[offset + 2] = (byte) (value >>> 8);
                    digest[offset + 3] = (byte) value;
                    assertEquals(value, Totp.truncate(digest));
                    digest[offset] &= 0x7f;
                    assertEquals(value, Totp.truncate(digest));
                }
            }
        }
        for (int length : new int[]{0, 3, 19, 21, 31, 63, 65}) {
            assertThrows(IllegalStateException.class, () -> Totp.truncate(new byte[length]));
        }
    }

    @Test
    void exactAsciiPaddingAndModulusUnderUnusualLocale() {
        Locale original = Locale.getDefault();
        try {
            Locale.setDefault(Locale.forLanguageTag("ar-EG-u-nu-arab"));
            for (int digits = 6; digits <= 8; digits++) {
                assertEquals("0".repeat(digits), Totp.decimalCode(0, digits));
                assertEquals("0".repeat(digits - 2) + "42", Totp.decimalCode(42, digits));
                assertEquals("0".repeat(digits - 1) + "5", Totp.decimalCode(5, digits));
                String full = "2147483647";
                assertEquals(full.substring(full.length() - digits), Totp.decimalCode(Integer.MAX_VALUE, digits));
                // SHA-1 RFC trial at 1111111109 also exercises padded generation.
                String expected = "07081804";
                assertEquals(expected.substring(8 - digits),
                        Totp.generate(credential(1, digits, 30), 1111111109));
            }
        } finally {
            Locale.setDefault(original);
        }
    }

    @Test
    void invalidProgrammerCreatedCredentialsFailIntentionally() {
        for (int algorithm : new int[]{-1, 0, 4, 255}) {
            assertThrows(IllegalArgumentException.class, () -> Totp.generate(credential(algorithm, 6, 30), 0));
        }
        for (int digits : new int[]{-1, 0, 5, 9}) {
            assertThrows(IllegalArgumentException.class, () -> Totp.generate(credential(1, digits, 30), 0));
        }
        for (long period : new long[]{-1, 0, 0x1_0000_0000L}) {
            assertThrows(IllegalArgumentException.class, () -> Totp.generate(credential(1, 6, period), 0));
        }
        for (int length : new int[]{0, 129}) {
            var c = new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[length], length));
            assertThrows(IllegalArgumentException.class, () -> Totp.generate(c, 0));
        }
    }

    @Test
    void rawSecretLengthExtremesAndImmutableOwnership() {
        for (int length : new int[]{1, 20, 128}) {
            byte[] input = new byte[length];
            Arrays.fill(input, (byte) 0xff); // Raw non-text key bytes, including Java-negative bytes.
            for (int algorithm = 1; algorithm <= 3; algorithm++) {
                var c = new TokenValue.Credential(algorithm, 8, 30, new SecurityBytes(input, input.length));
                byte[] callerCopy = c.secret().bytes();
                String expected = Totp.generate(c, 59);
                Arrays.fill(callerCopy, (byte) 0);
                assertArrayEquals(input, c.secret().bytes());
                assertEquals(expected, Totp.generate(c, 59));
                assertTrue(expected.matches("[0-9]{8}"));
            }
        }
        byte[] input = SECRET.clone();
        var c = new TokenValue.Credential(1, 8, 30, new SecurityBytes(input, input.length));
        Arrays.fill(input, (byte) 0);
        assertEquals("94287082", Totp.generate(c, 59));
        assertArrayEquals(SECRET, c.secret().bytes());
    }
}
