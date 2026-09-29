package dev.totipo.format;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/** Exact Unicode conversion with protocol limits measured in encoded bytes. */
final class StrictUtf8 {
    private StrictUtf8() {}

    static byte[] encode(String value, int maximum) {
        // Every well-formed UTF-16 code unit needs at least one UTF-8 byte.
        if (value.length() > maximum) throw new IllegalArgumentException("UTF-8 field too long");
        try {
            var encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
            if (encoded.remaining() > maximum) throw new IllegalArgumentException("UTF-8 field too long");
            byte[] bytes = new byte[encoded.remaining()];
            encoded.get(bytes);
            return bytes;
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid Unicode string", e);
        }
    }

    static String decode(byte[] bytes, int maximum) {
        if (bytes.length > maximum) throw new IllegalArgumentException("UTF-8 field too long");
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Invalid UTF-8", e);
        }
    }
}
