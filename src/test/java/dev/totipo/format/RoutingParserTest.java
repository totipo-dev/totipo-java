package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class RoutingParserTest {
    @Test
    void everyTruncatedFamilyPrefixIsIntentionallyUnroutableIncludingMaximumParents() {
        for (int version : new int[]{1, 2, 0, 255}) {
            for (int type : new int[]{1, 2}) {
                for (int count : new int[]{0, 1, 32}) {
                    byte[] prefix = prefix(version, type, count);
                    for (int length = 0; length < prefix.length; length++) {
                        var result = RoutingParser.parse(prefix, 0, length);
                        assertNull(result.prefix(), "version=" + version + " type=" + type + " length=" + length);
                        assertEquals(RoutingParser.Reason.TRUNCATED_PREFIX, result.reason());
                        assertEquals(version != 1 && length >= 5 ? RoutingParser.Outcome.OPAQUE_UNSCOPED
                                : RoutingParser.Outcome.MALFORMED, result.outcome());
                    }
                    assertEquals((type == 1 ? 100 : 64) + 36 * count, prefix.length);
                    assertRouted(prefix, version, type);
                }
            }
        }
    }

    @Test
    void futureOpaqueTailIsNeverParsedAsV1AndSupportedRoutingDoesNotValidateBodies() {
        for (int version : new int[]{1, 2, 255}) {
            for (int type : new int[]{1, 2}) {
                byte[] bytes = prefix(version, type, 0);
                // An impossible v1 field length followed by an incomplete header.
                byte[] withTail = Arrays.copyOf(bytes, bytes.length + 5);
                System.arraycopy(new byte[]{(byte) 0xff, 0, (byte) 0xff, (byte) 0xfe, (byte) 0x80},
                        0, withTail, bytes.length, 5);
                assertRouted(withTail, version, type);
                assertEquals(RoutingParser.parse(bytes).outcome(), RoutingParser.parse(withTail).outcome());
            }
        }
    }

    @Test
    void unknownTypeIsNotGivenTokenOrDeviceScopeOrScannedForAnIdentity() {
        for (int version : new int[]{0, 1, 2, 255}) {
            for (int type : new int[]{0, 3, 128, 255}) {
                byte[] bytes = prefix(version, 1, 0);
                bytes[9] = (byte) type;
                for (int length : new int[]{10, bytes.length}) {
                    var result = RoutingParser.parse(bytes, 0, length);
                    assertEquals(RoutingParser.Outcome.OPAQUE_UNSCOPED, result.outcome());
                    assertEquals(RoutingParser.Reason.UNKNOWN_TYPE, result.reason());
                    assertNull(result.prefix());
                }
            }
        }
    }

    @Test
    void eachFrozenFieldRequiresItsExactTagAndWidth() {
        for (int version : new int[]{1, 2}) {
            for (int type : new int[]{1, 2}) {
                byte[] valid = prefix(version, type, 1);
                int[] offsets = type == 1 ? new int[]{0, 5, 10, 16, 52, 64, 100}
                        : new int[]{0, 5, 10, 16, 52, 64};
                for (int offset : offsets) {
                    for (int changedByte : new int[]{offset, offset + 1, offset + 2, offset + 3}) {
                        byte[] broken = valid.clone();
                        broken[changedByte] ^= (byte) 0x80;
                        var result = RoutingParser.parse(broken);
                        assertNull(result.prefix(), "field at " + offset + " byte " + changedByte);
                        assertEquals(RoutingParser.Reason.MALFORMED_PREFIX, result.reason());
                        assertEquals(version != 1 && offset != 0 ? RoutingParser.Outcome.OPAQUE_UNSCOPED
                                : RoutingParser.Outcome.MALFORMED, result.outcome());
                    }
                }
            }
        }
    }

    @Test
    void countBoundsAndExactParentMultiplicityAreFrozen() {
        for (int count : new int[]{33, 128, 32768, 65535}) {
            byte[] broken = prefix(2, 1, 0);
            broken[14] = (byte) (count >>> 8);
            broken[15] = (byte) count;
            assertMalformedFuture(broken);
        }
        byte[] extraParent = prefix(2, 1, 1);
        extraParent[15] = 0;
        assertMalformedFuture(extraParent);
        byte[] missingParent = prefix(2, 1, 0);
        missingParent[15] = 1;
        assertMalformedFuture(missingParent);
    }

    @Test
    void changingKnownTypeRequiresTheOtherFamilysFrozenIdentityField() {
        for (int version : new int[]{1, 2}) {
            for (int type : new int[]{1, 2}) {
                byte[] bytes = prefix(version, type, 0);
                bytes[9] = (byte) (type == 1 ? 2 : 1);
                var result = RoutingParser.parse(bytes);
                assertNull(result.prefix());
                assertEquals(RoutingParser.Reason.MALFORMED_PREFIX, result.reason());
                assertEquals(version == 1 ? RoutingParser.Outcome.MALFORMED
                        : RoutingParser.Outcome.OPAQUE_UNSCOPED, result.outcome());
            }
        }
    }

    @Test
    void parentOrderingUsesUnsignedLexicographicBytesAndRejectsDuplicates() {
        byte[] bytes = prefix(2, 1, 2);
        Arrays.fill(bytes, 20, 52, (byte) 0x7f);
        Arrays.fill(bytes, 56, 88, (byte) 0x80);
        assertRouted(bytes, 2, 1);
        System.arraycopy(bytes, 20, bytes, 56, 32);
        assertMalformedFuture(bytes);
        bytes[20] = (byte) 0xff;
        assertMalformedFuture(bytes);
        // Compare all 32 bytes, not just the first byte of the ID.
        Arrays.fill(bytes, 20, 52, (byte) 0x80);
        Arrays.fill(bytes, 56, 88, (byte) 0x80);
        bytes[87] = (byte) 0x81;
        assertRouted(bytes, 2, 1);
        bytes[51] = (byte) 0xff;
        assertMalformedFuture(bytes);
    }

    @Test
    void valueChangesPreserveFullUnsignedTimeAndOpaqueIdentityBytes() {
        for (int type : new int[]{1, 2}) {
            byte[] bytes = prefix(255, type, 1);
            Arrays.fill(bytes, 20, 52, (byte) 0xff); // Parent ID has no semantic validation here.
            Arrays.fill(bytes, 56, 64, (byte) 0xff);
            Arrays.fill(bytes, 68, 100, (byte) 0x80);
            if (type == 1) {
                Arrays.fill(bytes, 104, 136, (byte) 0xff);
            }
            var parsed = RoutingParser.parse(bytes).prefix();
            assertEquals(255, parsed.version());
            assertEquals(new BigInteger("18446744073709551615"), parsed.authorTime());
            assertEquals((byte) 0x80, parsed.identity()[0]);
            assertEquals((byte) 0xff, parsed.parents().get(0)[0]);
            if (type == 1) {
                assertEquals((byte) 0xff, parsed.authorDeviceId()[0]);
            }
            bytes[56] = (byte) 0x80;
            Arrays.fill(bytes, 57, 64, (byte) 0);
            assertEquals(BigInteger.ONE.shiftLeft(63), RoutingParser.parse(bytes).prefix().authorTime());
        }
    }

    @Test
    void parsedFieldsAndConstructorInputsAreDefensivelyOwned() {
        byte[] source = prefix(2, 1, 1);
        var parsed = RoutingParser.parse(source).prefix();
        byte[] identity = parsed.identity();
        byte[] author = parsed.authorDeviceId();
        byte[] parent = parsed.parents().get(0);
        Arrays.fill(source, (byte) 0);
        parsed.identity()[0] ^= 1;
        parsed.authorDeviceId()[0] ^= 1;
        parsed.parents().get(0)[0] ^= 1;
        assertArrayEquals(identity, parsed.identity());
        assertArrayEquals(author, parsed.authorDeviceId());
        assertArrayEquals(parent, parsed.parents().get(0));
        assertThrows(UnsupportedOperationException.class, () -> parsed.parents().clear());
        var parents = new ArrayList<>(List.of(parent));
        var constructed = new RoutingPrefix(2, 1, parents, BigInteger.ZERO, identity, author);
        parents.clear();
        parent[0] ^= 1;
        identity[0] ^= 1;
        author[0] ^= 1;
        assertArrayEquals(parsed.identity(), constructed.identity());
        assertArrayEquals(parsed.authorDeviceId(), constructed.authorDeviceId());
        assertArrayEquals(parsed.parents().get(0), constructed.parents().get(0));
    }

    @Test
    void sliceBoundsAreRespectedEvenWhenBackingArrayHasACompletePrefix() {
        byte[] prefix = prefix(2, 2, 0);
        byte[] wrapped = new byte[prefix.length + 6];
        System.arraycopy(prefix, 0, wrapped, 3, prefix.length);
        assertNotNull(RoutingParser.parse(wrapped, 3, prefix.length).prefix());
        assertNull(RoutingParser.parse(wrapped, 3, prefix.length - 1).prefix());
        for (int[] slice : new int[][]{{-1, 0}, {0, -1}, {wrapped.length + 1, 0},
                {3, Integer.MAX_VALUE}, {Integer.MAX_VALUE, 2}}) {
            assertThrows(IndexOutOfBoundsException.class,
                    () -> RoutingParser.parse(wrapped, slice[0], slice[1]));
        }
    }

    private static void assertRouted(byte[] bytes, int version, int type) {
        var result = RoutingParser.parse(bytes);
        assertNotNull(result.prefix());
        assertEquals(RoutingParser.Reason.NONE, result.reason());
        assertEquals(version == 1
                ? (type == 1 ? RoutingParser.Outcome.SUPPORTED_V1_TOKEN : RoutingParser.Outcome.SUPPORTED_V1_DEVICE)
                : (type == 1 ? RoutingParser.Outcome.OPAQUE_ROUTABLE_TOKEN : RoutingParser.Outcome.OPAQUE_ROUTABLE_DEVICE),
                result.outcome());
    }

    private static void assertMalformedFuture(byte[] bytes) {
        var result = RoutingParser.parse(bytes);
        assertNull(result.prefix());
        assertEquals(RoutingParser.Outcome.OPAQUE_UNSCOPED, result.outcome());
        assertEquals(RoutingParser.Reason.MALFORMED_PREFIX, result.reason());
    }

    /** Independent fixture writer for exactly the normative prefix, not general TLV. */
    private static byte[] prefix(int version, int type, int parentCount) {
        var bytes = new ByteArrayOutputStream();
        field(bytes, 1, new byte[]{(byte) version});
        field(bytes, 2, new byte[]{(byte) type});
        field(bytes, 4, new byte[]{0, (byte) parentCount});
        for (int i = 0; i < parentCount; i++) {
            byte[] parent = new byte[32];
            parent[31] = (byte) i;
            field(bytes, 5, parent);
        }
        field(bytes, 6, new byte[8]);
        byte[] identity = new byte[32];
        Arrays.fill(identity, (byte) 0x82);
        field(bytes, type == 1 ? 0x0101 : 0x0200, identity);
        if (type == 1) {
            byte[] author = new byte[32];
            Arrays.fill(author, (byte) 0x91);
            field(bytes, 0x0102, author);
        }
        return bytes.toByteArray();
    }

    private static void field(ByteArrayOutputStream bytes, int tag, byte[] value) {
        bytes.write(tag >>> 8);
        bytes.write(tag);
        bytes.write(value.length >>> 8);
        bytes.write(value.length);
        bytes.writeBytes(value);
    }
}
