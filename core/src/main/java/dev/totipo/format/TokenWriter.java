package dev.totipo.format;

import java.util.Arrays;

/** Deterministic r16 semantic codec only; no identity generation or publication. */
final class TokenWriter {
    private TokenWriter() {}

    /** Caller owns the returned plaintext, including its secret bytes. */
    static byte[] write(TokenObject token) {
        // TokenObject and metadata constructors enforce all other immutable invariants.
        token.value().validate();
        var value = token.value();
        var credential = value.credential();
        byte[] secret = credential.secret().bytes();
        try (var fields = new TlvWriter()) {
            fields.field(1, token.tokenId().bytes()).field(2, integer(token.parents().size(), 2));
            for (ObjectId parent : token.parents()) fields.field(3, parent.bytes());
            fields.field(4, integer(value.status(), 1))
                    .field(5, StrictUtf8.encode(value.issuer(), 256))
                    .field(6, StrictUtf8.encode(value.account(), 256))
                    .field(7, integer(credential.algorithm(), 1))
                    .field(8, integer(credential.digits(), 1))
                    .field(9, integer(credential.period(), 4))
                    .field(10, secret);
            token.metadata().clientName().ifPresent(name -> fields.field(11, StrictUtf8.encode(name, 128)));
            token.metadata().clientTime().ifPresent(time -> fields.field(12, time.bytes()));
            return fields.bytes();
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    private static byte[] integer(long value, int width) {
        byte[] bytes = new byte[width];
        for (int i = width - 1; i >= 0; i--) {
            bytes[i] = (byte) value;
            value >>>= 8;
        }
        return bytes;
    }
}
