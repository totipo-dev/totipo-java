package org.totipo.format;

import static org.totipo.format.TlvTestBytes.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class TlvReaderTest {
    @Test
    void everyByteTruncationOfGenericFieldsIsBounded() {
        for (int tag : new int[]{0, 1, 0x8000, 0xffff}) {
            for (int length : new int[]{0, 1, 32, 1006}) {
                byte[] value = new byte[length];
                Arrays.fill(value, (byte) 0xff);
                checkTruncations(field(tag, value));
            }
        }
    }

    private static void checkTruncations(byte[] encoded) {
        for (int length = 0; length < encoded.length; length++) {
            // Extra backing bytes must not let a truncated slice succeed.
            var reader = new TlvReader(encoded, 0, length);
            var result = reader.next();
            assertEquals(length == 0 ? TlvReader.Status.END : length < 4
                    ? TlvReader.Status.TRUNCATED_HEADER : TlvReader.Status.TRUNCATED_VALUE, result.status());
            assertNull(result.field());
            assertEquals(result, reader.next(), "Failure/end must be terminal");
        }
        assertEquals(TlvReader.Status.FIELD, new TlvReader(encoded, 0, encoded.length).next().status());
    }

    @Test
    void concatenatedFieldsAdvanceExactlyWithoutImposingASchemaOrOrder() {
        byte[] bytes = join(field(0xffff, (byte) 0x80), field(0), field(0x8000, (byte) 0x7f, (byte) 0xff));
        assertArrayEquals(bytes, new TlvWriter().field(0xffff, new byte[]{(byte) 0x80})
                .field(0, new byte[0]).field(0x8000, new byte[]{0x7f, (byte) 0xff}).bytes());
        byte[] wrapped = join(new byte[7], bytes, new byte[3]);
        var reader = new TlvReader(wrapped, 7, bytes.length);
        for (int tag : new int[]{0xffff, 0, 0x8000}) {
            var result = reader.next();
            assertEquals(TlvReader.Status.FIELD, result.status());
            assertEquals(tag, result.field().tag());
        }
        assertEquals(TlvReader.Status.END, reader.next().status());
        assertArrayEquals(bytes, encode(fields(bytes)));
    }

    @Test
    void maximumUnsignedLengthIsCheckedBeforeAllocationAndNeverSignExtended() {
        byte[] bytes = field(0xffff, new byte[65535]);
        var value = new TlvReader(bytes, 0, bytes.length).next();
        assertEquals(TlvReader.Status.FIELD, value.status());
        assertEquals(65535, value.field().length());
        byte[] malicious = {(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff};
        assertEquals(TlvReader.Status.TRUNCATED_VALUE,
                new TlvReader(malicious, 0, malicious.length).next().status());
        assertEquals(TlvReader.Status.TRUNCATED_VALUE, new TlvReader(bytes, 0, bytes.length - 1).next().status());
        for (int[] slice : new int[][]{{-1, 0}, {0, -1}, {5, 0},
                {1, Integer.MAX_VALUE}, {Integer.MAX_VALUE, Integer.MAX_VALUE}}) {
            assertThrows(IndexOutOfBoundsException.class, () -> new TlvReader(malicious, slice[0], slice[1]));
        }
    }

    @Test
    void trailingPartialHeaderAndOversizedValueHaveDifferentIntentionalResults() {
        for (int length : new int[]{1, 2, 3}) {
            byte[] bytes = join(field(1), new byte[length]);
            var reader = new TlvReader(bytes, 0, bytes.length);
            assertEquals(TlvReader.Status.FIELD, reader.next().status());
            assertEquals(TlvReader.Status.TRUNCATED_HEADER, reader.next().status());
        }
        for (byte[] bytes : List.of(new byte[]{0, 1, 0, 1}, new byte[]{0, 1, (byte) 0x80, 0, 1})) {
            assertEquals(TlvReader.Status.TRUNCATED_VALUE, new TlvReader(bytes, 0, bytes.length).next().status());
        }
    }

    @Test
    void fieldValuesHaveIndependentOwnership() {
        byte[] bytes = field(1, (byte) 0x80, (byte) 0xff);
        var tlv = new TlvReader(bytes, 0, bytes.length).next().field();
        Arrays.fill(bytes, (byte) 0);
        tlv.value()[0] = 0;
        assertArrayEquals(new byte[]{(byte) 0x80, (byte) 0xff}, tlv.value());
        byte[] constructorInput = {3};
        var constructed = new TlvField(65535, constructorInput);
        constructorInput[0] = 9;
        assertArrayEquals(new byte[]{3}, constructed.value());
        assertThrows(IllegalArgumentException.class, () -> new TlvField(-1, new byte[0]));
        assertThrows(IllegalArgumentException.class, () -> new TlvField(65536, new byte[0]));
    }
}
