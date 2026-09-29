package dev.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

/** Single canonical DEVICE construction. Parent meaning/frontier policy is external. */
final class DeviceWriter {
    private DeviceWriter() {}

    static byte[] displayName(String name) {
        if (name == null || name.length() > 256) { throw new IllegalArgumentException("Invalid display name"); }
        byte[] bytes = PasswordBytes.encode(name.toCharArray());
        if (bytes == null || bytes.length > 256) { throw new IllegalArgumentException("Invalid display name"); }
        return bytes;
    }

    static List<ObjectId> canonicalParents(Collection<ObjectId> parents) {
        if (parents.size() > 32) { throw new IllegalArgumentException("Too many parents"); }
        var sorted = parents.stream().sorted(Comparator.comparing(ObjectId::filename)).toList();
        if (sorted.stream().distinct().count() != sorted.size()) {
            throw new IllegalArgumentException("Duplicate parents");
        }
        return sorted;
    }

    static void requireCapacity(int nameBytes, int parents) {
        if (nameBytes < 0 || nameBytes > 256 || parents < 0 || parents > 32
                || 213 + nameBytes + 36 * parents > EnvelopeReader.SEMANTIC_CAPACITY) {
            throw new IllegalArgumentException("DEVICE capacity exceeded");
        }
    }

    /** Guaranteed fan-in with the Section 45 72-byte signature reservation. */
    static int parentCapacity(int nameBytes) {
        requireCapacity(nameBytes, 0);
        int capacity = 0;
        while (capacity < 32) {
            try { requireCapacity(nameBytes, capacity + 1); }
            catch (IllegalArgumentException e) { break; }
            capacity++;
        }
        if (capacity < 2) { throw new IllegalStateException("DEVICE fold cannot make progress"); }
        return capacity;
    }

    /** Owns all mutable inputs and fixes shape before the only signing call. */
    static byte[] signed(byte[] root, DeviceIdentityResult identity, String name,
                         byte[] authorTime, Collection<ObjectId> parents) throws GeneralSecurityException {
        return signed(root, identity, displayName(name), authorTime, parents);
    }

    static byte[] signed(byte[] root, DeviceIdentityResult identity, byte[] name,
                         byte[] authorTime, Collection<ObjectId> parents) throws GeneralSecurityException {
        byte[] display = name.clone();
        if (display.length > 256 || !PasswordBytes.valid(display)) {
            throw new IllegalArgumentException("Invalid display name");
        }
        var ordered = canonicalParents(parents);
        requireCapacity(display.length, ordered.size());
        byte[] time = authorTime.clone();
        if (time.length != 8) { throw new IllegalArgumentException("AUTHOR_TIME width"); }
        byte[] key = identity.publicKeyX963();
        byte[] unsigned = unsigned(key, display, time, ordered);
        byte[] input = signatureInput(root, unsigned);
        try {
            byte[] signature = identity.signSha256Ecdsa(input);
            byte[] semantic = CryptoSupport.join(unsigned, new TlvWriter().field(0xff01, signature).bytes());
            return semantic;
        } finally { Arrays.fill(input, (byte) 0); }
    }

    private static byte[] unsigned(byte[] key, byte[] display, byte[] time, List<ObjectId> parents) {
        var tlv = new TlvWriter().field(1, new byte[]{1}).field(2, new byte[]{2})
                .field(4, new byte[]{0, (byte) parents.size()});
        for (var id : parents) { tlv.field(5, id.bytes()); }
        return tlv.field(6, time).field(0x0200, P256.deviceId(key))
                .field(0x0201, key).field(0x0202, display).bytes();
    }

    static byte[] signatureInput(byte[] root, byte[] unsigned) {
        return P256.signatureInput(root, 2, unsigned);
    }

}
