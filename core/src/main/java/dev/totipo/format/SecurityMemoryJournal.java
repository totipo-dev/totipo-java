package dev.totipo.format;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Private totipo-java format, NOT protocol TLV. Integers are big endian.
 * SHA-256 detects structural corruption, not replacement by a valid older journal. */
final class SecurityMemoryJournal {
    static final int PENDING = 1, ESTABLISHED = 2, UNKNOWN = 3, TOKEN = 4, DEVICE = 5, UNSCOPED = 6;
    static final int MAX_FRAME = 65536, MIN_FRAME = 77;
    private static final byte[] HEADER = {'T','O','T','I','P','O','-','S','M',0,0,1};
    private static final byte[] DOMAIN = "totipo-java/security-memory/frame/v1\0".getBytes(StandardCharsets.US_ASCII);
    enum Status { ABSENT, CLEAN, INCOMPLETE_TAIL, CORRUPT, UNSUPPORTED_LOCAL_FORMAT }
    record Replay(Status status, LocalEstablishment establishment, DurableKnowledgeState knowledge,
                  long sequence, SecurityBytes digest, long verifiedBytes, boolean corruptionForcedUnknown) {
        boolean repairRequired() { return status == Status.INCOMPLETE_TAIL; }
        @Override public String toString() {
            return "Replay[" + status + ", " + establishment.phase() + ", records=" + knowledge.size()
                    + ", sequence=" + sequence + ", verifiedBytes=" + verifiedBytes + "]";
        }
    }
    static byte[] header() { return HEADER.clone(); }
    static byte[] hash(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    static byte[] frame(long sequence, SecurityBytes previous, int type, byte[] payload) {
        if (sequence <= 0 || payload.length > MAX_FRAME - MIN_FRAME) { throw new IllegalArgumentException("Frame bounds"); }
        var out = ByteBuffer.allocate(MIN_FRAME + payload.length);
        out.putInt(out.capacity()).putLong(sequence).put((byte) type).put(previous.bytes()).put(payload);
        out.put(frameDigest(Arrays.copyOf(out.array(), out.position())));
        return out.array();
    }
    private static byte[] frameDigest(byte[] prefix) {
        var bytes = ByteBuffer.allocate(DOMAIN.length + HEADER.length + prefix.length);
        return hash(bytes.put(DOMAIN).put(HEADER).put(prefix).array());
    }
    static Replay replay(InputStream source) throws IOException {
        var establishment = LocalEstablishment.fresh();
        var knowledge = DurableKnowledgeState.establishedEmpty();
        long sequence = 0, offset = 0;
        boolean integrityFailure = false;
        var digest = new SecurityBytes(hash(HEADER), 32);
        if (source == null) { return result(Status.ABSENT, establishment, knowledge, sequence, digest, offset, integrityFailure); }
        var in = new DataInputStream(source);
        byte[] header = in.readNBytes(HEADER.length);
        if (header.length != HEADER.length || !Arrays.equals(Arrays.copyOf(header, 10), Arrays.copyOf(HEADER, 10))) {
            return result(Status.CORRUPT, establishment, knowledge, sequence, digest, offset, integrityFailure);
        }
        if (!Arrays.equals(header, HEADER)) {
            return result(Status.UNSUPPORTED_LOCAL_FORMAT, establishment, knowledge, sequence, digest, offset, integrityFailure);
        }
        offset = HEADER.length;
        while (true) {
            byte[] length = in.readNBytes(4);
            if (length.length == 0) {
                if (new GraphTopology(knowledge).integrity() == GraphIntegrityStatus.RESOLVED_CYCLE) {
                    knowledge = knowledge.localSecurityMemoryCorruption();
                    integrityFailure = true;
                }
                return result(Status.CLEAN, establishment, knowledge, sequence, digest, offset, integrityFailure);
            }
            if (length.length != 4) { return result(Status.INCOMPLETE_TAIL, establishment, knowledge, sequence, digest, offset, integrityFailure); }
            int size = ByteBuffer.wrap(length).getInt();
            if (size < MIN_FRAME || size > MAX_FRAME) { return result(Status.CORRUPT, establishment, knowledge, sequence, digest, offset, integrityFailure); }
            byte[] rest = in.readNBytes(size - 4); // bounded before allocation; no whole-journal buffering
            if (!possibleSize(size, rest)) {
                return result(Status.CORRUPT, establishment, knowledge, sequence, digest, offset, integrityFailure);
            }
            if (rest.length != size - 4) {
                // Reject detectable structural damage even in a short final suffix.
                if (rest.length >= 8 && (sequence == Long.MAX_VALUE || ByteBuffer.wrap(rest).getLong() != sequence + 1)
                        || rest.length >= 9 && (rest[8] < PENDING || rest[8] > UNSCOPED)
                        || rest.length >= 41 && !Arrays.equals(Arrays.copyOfRange(rest, 9, 41), digest.bytes())) {
                    return result(Status.CORRUPT, establishment, knowledge, sequence, digest, offset, integrityFailure);
                }
                return result(Status.INCOMPLETE_TAIL, establishment, knowledge, sequence, digest, offset, integrityFailure);
            }
            byte[] frame = ByteBuffer.allocate(size).put(length).put(rest).array();
            var cursor = ByteBuffer.wrap(rest);
            long nextSequence = cursor.getLong();
            int type = Byte.toUnsignedInt(cursor.get());
            byte[] previous = new byte[32]; cursor.get(previous);
            byte[] nextDigest = Arrays.copyOfRange(frame, size - 32, size);
            if (sequence == Long.MAX_VALUE || nextSequence != sequence + 1 || !Arrays.equals(previous, digest.bytes())
                    || !Arrays.equals(nextDigest, frameDigest(Arrays.copyOf(frame, size - 32)))) {
                return result(Status.CORRUPT, establishment, knowledge, sequence, digest, offset, integrityFailure);
            }
            if (type < PENDING || type > UNSCOPED) {
                return result(Status.UNSUPPORTED_LOCAL_FORMAT, establishment, knowledge, sequence, digest, offset, integrityFailure);
            }
            try {
                var payload = new DataInputStream(new ByteArrayInputStream(frame, 45, size - MIN_FRAME));
                if (type == PENDING || type == ESTABLISHED) {
                    var binding = bytes(payload, 32);
                    requireEnd(payload);
                    establishment = establishment.transition(type == PENDING ? LocalEstablishment.Phase.PENDING
                            : LocalEstablishment.Phase.ESTABLISHED, binding);
                } else if (type == UNKNOWN) {
                    requireEnd(payload);
                    knowledge = knowledge.localSecurityMemoryCorruption();
                } else {
                    if (establishment.phase() != LocalEstablishment.Phase.ESTABLISHED) { throw new IllegalArgumentException(); }
                    var record = decode(type, payload);
                    requireEnd(payload);
                    var update = knowledge.afterRecordPersistence(record, DurableKnowledgeState.PersistenceResult.COMMITTED);
                    knowledge = update.state();
                    integrityFailure |= update.outcome() == DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN;
                    // Ordinary replay cannot reclassify unscoped evidence either.
                    if (update.outcome() == DurableKnowledgeState.Outcome.RECLASSIFICATION_REQUIRED) {
                        knowledge = knowledge.localSecurityMemoryCorruption();
                        integrityFailure = true;
                    }
                }
            } catch (IllegalArgumentException | IOException e) {
                return result(Status.CORRUPT, establishment, knowledge, sequence, digest, offset, integrityFailure);
            }
            sequence = nextSequence; digest = new SecurityBytes(nextDigest, 32); offset += size;
        }
    }
    private static Replay result(Status status, LocalEstablishment e, DurableKnowledgeState k,
                                 long sequence, SecurityBytes digest, long offset, boolean integrityFailure) {
        boolean corrupt = status == Status.CORRUPT || status == Status.UNSUPPORTED_LOCAL_FORMAT;
        if (corrupt) { k = k.localSecurityMemoryCorruption(); }
        return new Replay(status, e, k, sequence, digest, offset,
                corrupt || integrityFailure);
    }
    /** Validate redundant typed size information as soon as the prefix contains it. */
    private static boolean possibleSize(int size, byte[] rest) {
        if (rest.length < 9) { return true; }
        int type = Byte.toUnsignedInt(rest[8]);
        if (type == PENDING || type == ESTABLISHED) { return size == MIN_FRAME + 32; }
        if (type == UNKNOWN) { return size == MIN_FRAME; }
        if (type == UNSCOPED) { return size == MIN_FRAME + 1056; }
        if ((type == TOKEN || type == DEVICE) && rest.length >= 109) {
            int count = Short.toUnsignedInt(ByteBuffer.wrap(rest, 107, 2).getShort());
            if (count > 32) { return false; }
            if (type == TOKEN) { return size == MIN_FRAME + 108 + 32 * count; }
            int keyOffset = 41 + 76 + 32 * count;
            if (rest.length > keyOffset) {
                int keyLength = Byte.toUnsignedInt(rest[keyOffset]);
                return (keyLength == 0 || keyLength == 65) && size == MIN_FRAME + 77 + 32 * count + keyLength;
            }
        }
        return true;
    }
    static int type(DurableRecord record) {
        return record instanceof KnownTokenNode ? TOKEN : record instanceof KnownDeviceNode ? DEVICE : UNSCOPED;
    }
    static byte[] encode(DurableRecord record) {
        try {
            var buffer = new ByteArrayOutputStream(); var out = new DataOutputStream(buffer);
            out.write(record.objectId().bytes());
            if (record instanceof OpaqueUnscopedRecord r) { out.write(r.exactObjectBytes().bytes()); }
            else if (record instanceof KnownTokenNode r) {
                routing(out, r.objectVersion(), r.semanticStatus(), r.tokenId(), r.parents());
                out.write(r.authorDeviceId().bytes()); out.writeLong(r.authorTime().longValue());
            } else if (record instanceof KnownDeviceNode r) {
                routing(out, r.objectVersion(), r.semanticStatus(), r.deviceId(), r.parents());
                out.writeLong(r.authorTime().longValue());
                out.writeByte(r.publicKeyX963() == null ? 0 : 65);
                if (r.publicKeyX963() != null) { out.write(r.publicKeyX963().bytes()); }
            }
            return buffer.toByteArray();
        } catch (IOException e) { throw new AssertionError(e); }
    }
    private static void routing(DataOutputStream out, int version, SemanticStatus status,
                                SecurityBytes identity, List<ObjectId> parents) throws IOException {
        // A protocol envelope cannot contain more than 1024/32 parent IDs.
        if (parents.size() > 32) { throw new IllegalArgumentException("Parent count exceeds envelope bound"); }
        out.writeByte(version); out.writeByte(status == SemanticStatus.SUPPORTED_VALID ? 1 : 2);
        out.write(identity.bytes()); out.writeShort(parents.size());
        for (var id : parents) { out.write(id.bytes()); }
    }
    private static DurableRecord decode(int type, DataInputStream in) throws IOException {
        var id = new ObjectId(bytes(in, 32).bytes());
        if (type == UNSCOPED) { return new OpaqueUnscopedRecord(id, bytes(in, 1024)); }
        int version = in.readUnsignedByte(), statusByte = in.readUnsignedByte();
        if (statusByte != 1 && statusByte != 2) { throw new IllegalArgumentException(); }
        var status = statusByte == 1 ? SemanticStatus.SUPPORTED_VALID : SemanticStatus.OPAQUE_ROUTABLE;
        var identity = bytes(in, 32);
        int count = in.readUnsignedShort();
        if (count > 32) { throw new IllegalArgumentException(); }
        var parents = new ArrayList<ObjectId>();
        for (int i = 0; i < count; i++) { parents.add(new ObjectId(bytes(in, 32).bytes())); }
        if (type == TOKEN) { return new KnownTokenNode(id, version, status, identity, parents, bytes(in, 32), time(in)); }
        var time = time(in); int keyLength = in.readUnsignedByte();
        if (keyLength != 0 && keyLength != 65) { throw new IllegalArgumentException(); }
        return new KnownDeviceNode(id, version, status, identity, parents, time, keyLength == 0 ? null : bytes(in, 65));
    }
    private static BigInteger time(DataInputStream in) throws IOException { return new BigInteger(1, bytes(in, 8).bytes()); }
    private static SecurityBytes bytes(DataInputStream in, int count) throws IOException {
        byte[] b = new byte[count]; in.readFully(b); return new SecurityBytes(b, count);
    }
    private static void requireEnd(DataInputStream in) throws IOException { if (in.read() != -1) { throw new IllegalArgumentException(); } }
}
