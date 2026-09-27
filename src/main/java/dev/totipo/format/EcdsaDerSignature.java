package dev.totipo.format;

/** Narrow canonical DER SEQUENCE { INTEGER r, INTEGER s }; no general ASN.1. */
final class EcdsaDerSignature {
    private EcdsaDerSignature() {}

    static boolean isCanonical(byte[] signature) {
        // Two one-octet integers need 8 bytes. The protocol caps the field at 72.
        // Consequently every canonical length is short form (less than 128).
        if (signature.length < 8 || signature.length > 72 || signature[0] != 0x30
                || (signature[1] & 0xff) != signature.length - 2) {
            return false;
        }
        int offset = integerEnd(signature, 2);
        if (offset < 0) { return false; }
        return integerEnd(signature, offset) == signature.length;
    }

    private static int integerEnd(byte[] bytes, int offset) {
        if (offset + 2 > bytes.length || bytes[offset] != 2) { return -1; }
        int length = bytes[offset + 1] & 0xff;
        int start = offset + 2;
        if (length == 0 || length >= 128 || length > bytes.length - start) { return -1; }
        if ((bytes[start] & 0x80) != 0) { return -1; }
        if (length > 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0) { return -1; }
        // Canonical zero and out-of-range scalars are mathematical failures, not DER failures.
        return start + length;
    }
}
