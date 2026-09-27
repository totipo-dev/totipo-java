package dev.totipo.format;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;

/** Owned 32-byte keyed semantic identity (§13), distinct from its filename encoding. */
final class ObjectId {
    private final byte[] bytes;

    ObjectId(byte[] bytes) {
        if (bytes.length != 32) {
            throw new IllegalArgumentException("Object ID must be 32 bytes");
        }
        this.bytes = bytes.clone();
    }

    static ObjectId fromFilename(String filename) {
        if (filename.length() != 64 || !filename.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Invalid object filename");
        }
        return new ObjectId(HexFormat.of().parseHex(filename));
    }

    static ObjectId compute(byte[] idKey, byte[] semantic) {
        if (idKey.length != 32) {
            throw new IllegalArgumentException("Identity key must be 32 bytes");
        }
        return new ObjectId(CryptoSupport.hmac(idKey, semantic));
    }

    boolean authenticates(byte[] idKey, byte[] semantic) {
        byte[] computed = CryptoSupport.hmac(idKey, semantic);
        try {
            return MessageDigest.isEqual(bytes, computed);
        } finally {
            Arrays.fill(computed, (byte) 0);
        }
    }

    byte[] bytes() { return bytes.clone(); }

    String filename() { return HexFormat.of().formatHex(bytes); }

    @Override
    public boolean equals(Object other) {
        return other instanceof ObjectId id && Arrays.equals(bytes, id.bytes);
    }

    @Override
    public int hashCode() { return Arrays.hashCode(bytes); }
}
