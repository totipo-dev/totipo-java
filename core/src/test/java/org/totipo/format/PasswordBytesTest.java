package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class PasswordBytesTest {
    @Test
    void exactUtf8DomainAndBoundaries() {
        for (String text : new String[]{"", "ascii", "é密碼😀", "a".repeat(1024),
                "a".repeat(1022) + "é", "a".repeat(1020) + "😀", " leading trailing ", "\0"}) {
            byte[] expected = text.getBytes(StandardCharsets.UTF_8);
            char[] characters = text.toCharArray();
            char[] before = characters.clone();
            assertTrue(PasswordBytes.valid(expected));
            assertArrayEquals(expected, PasswordBytes.encode(characters));
            assertArrayEquals(before, characters);
        }
        for (String text : new String[]{"a".repeat(1025), "a".repeat(1023) + "é",
                "a".repeat(1021) + "😀"}) {
            assertFalse(PasswordBytes.valid(text.getBytes(StandardCharsets.UTF_8)));
            assertNull(PasswordBytes.encode(text.toCharArray()));
        }
    }

    @Test
    void malformedUtf8IsNeverReplaced() {
        for (String hex : new String[]{"ff", "80", "c241", "e282", "c0af", "eda080", "f4908080"}) {
            byte[] bytes = HexFormat.of().parseHex(hex);
            byte[] before = bytes.clone();
            assertFalse(PasswordBytes.valid(bytes));
            assertArrayEquals(before, bytes);
        }
    }

    @Test
    void unpairedSurrogatesAreNeverReplaced() {
        for (char[] characters : new char[][]{{'\ud800'}, {'\udc00'}, {'a', '\ud800', 'b'}}) {
            assertNull(PasswordBytes.encode(characters));
        }
    }

    @Test
    void noNormalizationTrimmingOrCaseFolding() {
        assertFalse(Arrays.equals(PasswordBytes.encode(new char[]{'é'}),
                PasswordBytes.encode(new char[]{'e', '\u0301'})));
        assertArrayEquals(new byte[]{32, 65, 0, 32}, PasswordBytes.encode(new char[]{' ', 'A', 0, ' '}));
    }
}
