package dev.totipo.format;

import java.io.ByteArrayOutputStream;

/** Canonical u16be tag/length framing; schema ordering belongs to the semantic writer. */
final class TlvWriter {
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

    TlvWriter field(int tag, byte[] value) {
        var field = new TlvField(tag, value);
        if (field.length() > 0xffff) { throw new IllegalArgumentException("TLV too large"); }
        bytes.write(tag >>> 8); bytes.write(tag);
        bytes.write(field.length() >>> 8); bytes.write(field.length());
        bytes.writeBytes(field.value());
        return this;
    }
    byte[] bytes() { return bytes.toByteArray(); }
}
