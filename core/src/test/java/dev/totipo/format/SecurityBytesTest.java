package dev.totipo.format;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SecurityBytesTest {
    @Test void stringIsConstantAcrossContentsAndLengthsWhileValueSemanticsRemain() {
        byte[] longSecret = new byte[128];
        Arrays.fill(longSecret, (byte) 42);
        var a = new SecurityBytes(new byte[]{0}, 1);
        var b = new SecurityBytes(new byte[]{1}, 1);
        var longer = new SecurityBytes(longSecret, longSecret.length);
        assertNotEquals(a.hashCode(), b.hashCode());
        for (var secret : new SecurityBytes[]{a, b, longer}) {
            assertEquals("SecurityBytes[redacted]", secret.toString());
            assertFalse(secret.toString().contains(Integer.toHexString(secret.hashCode())));
        }
        assertEquals(a, new SecurityBytes(new byte[]{0}, 1));
        assertEquals(a.hashCode(), new SecurityBytes(new byte[]{0}, 1).hashCode());
        assertNotEquals(a, b);
    }
}
