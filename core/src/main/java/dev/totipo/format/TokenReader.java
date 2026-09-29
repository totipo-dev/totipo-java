package dev.totipo.format;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Optional;

/** Exact r16 TOKEN grammar. Borrows P synchronously; retains only owned model values. */
final class TokenReader {
    private TokenReader() {}

    /** Rejects malformed/noncanonical input with IllegalArgumentException. */
    static TokenObject read(byte[] semantic) {
        if (semantic.length > TokenObject.MAX_SEMANTIC_BYTES) throw invalid();
        var fields = new TlvReader(semantic, 0, semantic.length);
        var tokenId = new TokenId(field(fields.next(), 1, 32, 32));
        int count = (int) number(fields.next(), 2, 2);
        if (count > TokenObject.MAX_PARENTS) throw invalid();
        var parents = new ArrayList<ObjectId>(count);
        for (int i = 0; i < count; i++) {
            parents.add(new ObjectId(field(fields.next(), 3, 32, 32)));
        }
        int status = (int) number(fields.next(), 4, 1);
        String issuer = StrictUtf8.decode(field(fields.next(), 5, 0, 256), 256);
        String account = StrictUtf8.decode(field(fields.next(), 6, 0, 256), 256);
        int algorithm = (int) number(fields.next(), 7, 1);
        int digits = (int) number(fields.next(), 8, 1);
        long period = number(fields.next(), 9, 4);
        byte[] secret = field(fields.next(), 10, 1, 128);
        try {
            Optional<String> name = Optional.empty();
            Optional<UInt64> time = Optional.empty();
            var next = fields.next();
            if (hasTag(next, 11)) {
                name = Optional.of(StrictUtf8.decode(field(next, 11, 0, 128), 128));
                next = fields.next();
            }
            if (hasTag(next, 12)) {
                time = Optional.of(UInt64.fromBytes(field(next, 12, 8, 8)));
                next = fields.next();
            }
            if (next.status() != TlvReader.Status.END) {
                if (next.field() != null) next.field().clear();
                throw invalid();
            }
            return new TokenObject(tokenId, parents,
                    new TokenValue(status, issuer, account,
                            new TokenValue.Credential(algorithm, digits, period,
                                    new SecurityBytes(secret, secret.length))),
                    new TokenMetadata(name, time));
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private static boolean hasTag(TlvReader.Result result, int tag) {
        return result.status() == TlvReader.Status.FIELD && result.field().tag() == tag;
    }

    private static byte[] field(TlvReader.Result result, int tag, int minimum, int maximum) {
        var field = result.field();
        try {
            if (!hasTag(result, tag) || field.length() < minimum || field.length() > maximum) {
                throw invalid();
            }
            return field.value();
        } finally {
            if (field != null) field.clear();
        }
    }

    private static long number(TlvReader.Result result, int tag, int width) {
        byte[] value = field(result, tag, width, width);
        long number = 0;
        for (byte b : value) number = (number << 8) | (b & 0xffL);
        return number;
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid canonical TOKEN");
    }
}
