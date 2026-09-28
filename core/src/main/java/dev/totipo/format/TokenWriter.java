package dev.totipo.format;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/** Canonical r15 TOKEN encoding; graph and publication policy are external. */
final class TokenWriter {
    private TokenWriter() {}

    static void requireCapacity(TokenValue value, int parents) {
        int issuer = DeviceWriter.displayName(value.issuer()).length;
        int account = DeviceWriter.displayName(value.account()).length;
        var c = value.credential();
        if ((value.status() != 1 && value.status() != 2) || c.algorithm() < 1 || c.algorithm() > 3
                || c.digits() < 6 || c.digits() > 8 || c.period() < 1 || c.period() > 0xffffffffL
                || c.secret().size() < 1 || c.secret().size() > 128) {
            throw new IllegalArgumentException("Invalid TOKEN value");
        }
        if (parents < 0 || parents > 32 || 215 + issuer + account + c.secret().size() + 36 * parents
                > EnvelopeReader.SEMANTIC_CAPACITY) {
            throw new IllegalArgumentException("TOKEN capacity exceeded");
        }
    }

    static byte[] signed(byte[] root, DeviceIdentityResult identity, byte[] tokenId, TokenValue value,
                         byte[] authorTime, Collection<ObjectId> parents) throws GeneralSecurityException {
        byte[] id = tokenId.clone(), time = authorTime.clone();
        if (id.length != 32 || time.length != 8) { throw new IllegalArgumentException("TOKEN identity/time width"); }
        var ordered = DeviceWriter.canonicalParents(parents);
        requireCapacity(value, ordered.size());
        byte[] key = identity.publicKeyX963();
        byte[] unsigned = unsigned(id, P256.deviceId(key), value, time, ordered);
        byte[] input = P256.signatureInput(root, 1, unsigned);
        try {
            byte[] signature = identity.signSha256Ecdsa(input);
            byte[] semantic = CryptoSupport.join(unsigned, new TlvWriter().field(0xff01, signature).bytes());
            return semantic;
        } finally { Arrays.fill(input, (byte) 0); Arrays.fill(unsigned, (byte) 0); }
    }

    private static byte[] unsigned(byte[] id, byte[] author, TokenValue value, byte[] time, List<ObjectId> parents) {
        var c = value.credential();
        byte[] secret = c.secret().bytes();
        byte[] nested = null;
        try {
            nested = new TlvWriter().field(0x0301, new byte[]{(byte) c.algorithm()})
                    .field(0x0302, new byte[]{(byte) c.digits()})
                    .field(0x0303, ByteBuffer.allocate(4).putInt((int) c.period()).array())
                    .field(0x0304, secret).bytes();
            var tlv = new TlvWriter().field(1, new byte[]{1}).field(2, new byte[]{1})
                    .field(4, new byte[]{0, (byte) parents.size()});
            for (var parent : parents) { tlv.field(5, parent.bytes()); }
            return tlv.field(6, time).field(0x0101, id).field(0x0102, author)
                    .field(0x0103, new byte[]{(byte) value.status()})
                    .field(0x0104, DeviceWriter.displayName(value.issuer()))
                    .field(0x0105, DeviceWriter.displayName(value.account())).field(0x0106, nested).bytes();
        } finally { Arrays.fill(secret, (byte) 0); if (nested != null) { Arrays.fill(nested, (byte) 0); } }
    }

}
