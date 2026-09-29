package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/** Test fixture assembly preserves supplied order, including deliberate invalid encodings. */
final class TlvTestBytes {
    private TlvTestBytes() {}

    static byte[] field(int tag, byte... value) {
        var out = new ByteArrayOutputStream();
        out.write(tag >>> 8);
        out.write(tag);
        out.write(value.length >>> 8);
        out.write(value.length);
        out.writeBytes(value);
        return out.toByteArray();
    }

    static byte[] join(byte[]... parts) {
        var out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    static List<TlvField> fields(byte[] bytes) {
        var reader = new TlvReader(bytes, 0, bytes.length);
        var fields = new ArrayList<TlvField>();
        while (true) {
            var result = reader.next();
            if (result.status() == TlvReader.Status.END) {
                return fields;
            }
            assertEquals(TlvReader.Status.FIELD, result.status());
            fields.add(result.field());
        }
    }

    static byte[] encode(List<TlvField> fields) {
        var out = new ByteArrayOutputStream();
        for (var value : fields) {
            out.writeBytes(field(value.tag(), value.value()));
        }
        return out.toByteArray();
    }

}
