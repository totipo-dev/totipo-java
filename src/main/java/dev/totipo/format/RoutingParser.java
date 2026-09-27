package dev.totipo.format;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Reads semantic plaintext only (r10 §§12, 15, 41–43). Authentication/envelope
 * validation is a separate prerequisite for treating these bytes as evidence.
 * Kept internal until a complete object reader defines the public boundary.
 */
final class RoutingParser {
    private RoutingParser() {}

    enum Outcome {
        SUPPORTED_V1_TOKEN, SUPPORTED_V1_DEVICE,
        OPAQUE_ROUTABLE_TOKEN, OPAQUE_ROUTABLE_DEVICE,
        OPAQUE_UNSCOPED, MALFORMED
    }

    enum Reason { NONE, UNKNOWN_TYPE, MALFORMED_PREFIX, TRUNCATED_PREFIX }

    // The consumed length lets supported-body parsing start at the proven boundary
    // without duplicating the frozen layout or rereading its fields.
    record Result(Outcome outcome, RoutingPrefix prefix, Reason reason, int prefixLength) {}

    static Result parse(byte[] semanticBytes) {
        return parse(semanticBytes, 0, semanticBytes.length);
    }

    static Result parse(byte[] semanticBytes, int offset, int length) {
        var bytes = new ByteCursor(semanticBytes, offset, length);
        int version = -1;
        try {
            if (!field(bytes, 0x0001, 1)) {
                return malformed(version, Reason.MALFORMED_PREFIX);
            }
            version = bytes.u8();
            if (!field(bytes, 0x0002, 1)) {
                return malformed(version, Reason.MALFORMED_PREFIX);
            }
            int type = bytes.u8();
            if (type != 1 && type != 2) {
                // No known family grammar or identity scope may be guessed from the tail.
                return new Result(Outcome.OPAQUE_UNSCOPED, null, Reason.UNKNOWN_TYPE, 0);
            }
            if (!field(bytes, 0x0004, 2)) {
                return malformed(version, Reason.MALFORMED_PREFIX);
            }
            int count = bytes.u16be();
            if (count > 32) {
                return malformed(version, Reason.MALFORMED_PREFIX);
            }
            // Allocation is bounded by the frozen count limit, never an unchecked wire length.
            var parents = new ArrayList<byte[]>(count);
            byte[] previous = null;
            for (int i = 0; i < count; i++) {
                if (!field(bytes, 0x0005, 32)) {
                    return malformed(version, Reason.MALFORMED_PREFIX);
                }
                byte[] parent = bytes.copy(32);
                if (previous != null && Arrays.compareUnsigned(previous, parent) >= 0) {
                    return malformed(version, Reason.MALFORMED_PREFIX);
                }
                parents.add(parent);
                previous = parent;
            }
            if (!field(bytes, 0x0006, 8)) {
                return malformed(version, Reason.MALFORMED_PREFIX);
            }
            var time = bytes.u64be();
            if (!field(bytes, type == 1 ? 0x0101 : 0x0200, 32)) {
                return malformed(version, Reason.MALFORMED_PREFIX);
            }
            byte[] identity = bytes.copy(32);
            byte[] author = null;
            if (type == 1) {
                if (!field(bytes, 0x0102, 32)) {
                    return malformed(version, Reason.MALFORMED_PREFIX);
                }
                author = bytes.copy(32);
            }
            var prefix = new RoutingPrefix(version, type, parents, time, identity, author);
            // Stop here for EVERY version. In particular an unsupported version's opaque
            // tail MUST NOT be parsed as v1. Even supported routing is not full validity.
            Outcome outcome = version == 1
                    ? (type == 1 ? Outcome.SUPPORTED_V1_TOKEN : Outcome.SUPPORTED_V1_DEVICE)
                    : (type == 1 ? Outcome.OPAQUE_ROUTABLE_TOKEN : Outcome.OPAQUE_ROUTABLE_DEVICE);
            return new Result(outcome, prefix, Reason.NONE, bytes.position() - offset);
        } catch (ByteCursor.TruncatedInput e) {
            return malformed(version, Reason.TRUNCATED_PREFIX);
        }
    }

    private static Result malformed(int version, Reason reason) {
        // Incompatible unsupported semantics are unscoped, not supported-invalid (§12.4).
        return new Result(version >= 0 && version != 1 ? Outcome.OPAQUE_UNSCOPED : Outcome.MALFORMED,
                null, reason, 0);
    }

    /** Exact frozen field framing only; deliberately not a general TLV reader. */
    private static boolean field(ByteCursor bytes, int tag, int width) throws ByteCursor.TruncatedInput {
        bytes.require(4);
        int actualTag = bytes.u16be();
        int actualWidth = bytes.u16be();
        if (actualTag != tag || actualWidth != width) {
            return false;
        }
        // Header plus the entire fixed value is checked before any value read/allocation.
        bytes.require(width);
        return true;
    }
}
