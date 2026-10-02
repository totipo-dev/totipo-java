package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;

class ByteCursorTest {
    @Test
    void unsignedU32ReadsAreBigEndianBoundedAndAtomicOnTruncation() throws Exception {
        byte[] bytes = {9, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 9};
        var cursor = new ByteCursor(bytes, 1, 4);
        assertEquals(1, cursor.position());
        assertEquals(4, cursor.remaining());
        assertEquals(4294967295L, cursor.u32be());
        assertEquals(5, cursor.position());
        assertEquals(0, cursor.remaining());
        assertEquals(0x01020304L, new ByteCursor(new byte[]{1, 2, 3, 4}, 0, 4).u32be());
        for (int length = 0; length < 4; length++) {
            var shortSlice = new ByteCursor(bytes, 1, length);
            assertThrows(ByteCursor.TruncatedInput.class, shortSlice::u32be);
            assertEquals(1, shortSlice.position());
            assertEquals(length, shortSlice.remaining());
        }
    }

    @Test
    void invalidJavaSlicesAreProgrammerErrorsEvenWhenAdditionWouldOverflow() {
        byte[] bytes = new byte[8];
        for (int[] slice : new int[][]{{-1, 0}, {0, -1}, {9, 0}, {7, 2},
                {1, Integer.MAX_VALUE}, {Integer.MAX_VALUE, Integer.MAX_VALUE}}) {
            assertThrows(IndexOutOfBoundsException.class, () -> new ByteCursor(bytes, slice[0], slice[1]));
        }
        assertThrows(NullPointerException.class, () -> new ByteCursor(null, 0, 0));
    }

    @Test
    void truncatedReadsAreIntentionalAndDoNotAdvanceOrTruncate() throws Exception {
        var empty = new ByteCursor(new byte[0], 0, 0);
        assertEquals(0, empty.copy(0).length);
        assertThrows(ByteCursor.TruncatedInput.class, empty::u8);
        var bytes = new ByteCursor(new byte[]{1, 2, 3, 4}, 1, 2);
        assertThrows(ByteCursor.TruncatedInput.class, bytes::u64be);
        assertThrows(ByteCursor.TruncatedInput.class, () -> bytes.copy(Integer.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> bytes.copy(-1));
        assertEquals(0x0203, bytes.u16be());
        assertThrows(ByteCursor.TruncatedInput.class, bytes::u16be);
        var last = new ByteCursor(new byte[]{7}, 0, 1);
        assertThrows(ByteCursor.TruncatedInput.class, last::u16be);
        assertEquals(7, last.u8());
        var end = new ByteCursor(new byte[4], 4, 0);
        assertThrows(ByteCursor.TruncatedInput.class, end::u8);
    }

    @Test
    void highBitsRemainUnsignedAndSlicesNeverExposeStorage() throws Exception {
        byte[] source = {(byte) 0x80, (byte) 0xff, (byte) 0xfe};
        var bytes = new ByteCursor(source, 0, source.length);
        assertEquals(128, bytes.u8());
        assertEquals(65534, bytes.u16be());
        byte[] allBits = new byte[8];
        java.util.Arrays.fill(allBits, (byte) 0xff);
        assertEquals(new BigInteger("18446744073709551615"), new ByteCursor(allBits, 0, 8).u64be());
        byte[] slice = new ByteCursor(source, 1, 2).copy(2);
        source[1] = 0;
        assertEquals((byte) 0xff, slice[0]);
        slice[1] = 0;
        assertEquals((byte) 0xfe, source[2]);
    }
}
