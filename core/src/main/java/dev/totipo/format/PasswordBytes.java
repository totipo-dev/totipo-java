package dev.totipo.format;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Strict r14 §6 encoding. Borrows caller input; owned encodings must be cleared by the caller. */
final class PasswordBytes {
    static final int MAX_BYTES = 1024;

    private PasswordBytes() {}

    static boolean valid(byte[] bytes) {
        if (bytes.length > MAX_BYTES) {
            return false;
        }
        var decoded = CharBuffer.allocate(MAX_BYTES);
        try {
            var decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            var result = decoder.decode(ByteBuffer.wrap(bytes), decoded, true);
            return !result.isError() && !result.isOverflow() && !decoder.flush(decoded).isError();
        } finally {
            Arrays.fill(decoded.array(), '\0');
        }
    }

    /** Returns an owned exact encoding, or null for invalid input. Never modifies the characters. */
    static byte[] encode(char[] characters) {
        // Every valid UTF-16 code unit needs at least one UTF-8 byte.
        if (characters.length > MAX_BYTES) {
            return null;
        }
        var encoded = ByteBuffer.allocate(MAX_BYTES);
        try {
            var encoder = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            var result = encoder.encode(CharBuffer.wrap(characters), encoded, true);
            if (result.isOverflow()) {
                return null;
            }
            if (result.isError()) { result.throwException(); }
            result = encoder.flush(encoded);
            if (result.isOverflow()) {
                return null;
            }
            if (result.isError()) { result.throwException(); }
            return Arrays.copyOf(encoded.array(), encoded.position());
        } catch (CharacterCodingException e) {
            return null;
        } finally {
            Arrays.fill(encoded.array(), (byte) 0);
        }
    }
}
