package dev.totipo.format;

import java.util.Arrays;

/** Immutable, fixed non-TLV r13 §8 bootstrap. Contains no password or plaintext root. */
final class VaultBootstrap {
    static final int RECORD_BYTES = 87;
    static final int HEADER_BYTES = 39;
    private final byte[] record;

    private VaultBootstrap(byte[] ownedRecord) {
        record = ownedRecord;
    }

    /** Cheap preflight only; null means invalid format. Takes a defensive snapshot. */
    static VaultBootstrap parse(byte[] input) {
        if (input.length != RECORD_BYTES) {
            return null;
        }
        byte[] snapshot = input.clone();
        byte[] magic = CryptoSupport.ascii("TOTIPO-VLT");
        for (int i = 0; i < magic.length; i++) {
            if (snapshot[i] != magic[i]) {
                return null;
            }
        }
        if (snapshot[10] != 1) {
            return null;
        }
        return new VaultBootstrap(snapshot);
    }

    byte[] salt() { return Arrays.copyOfRange(record, 11, 27); }
    byte[] nonce() { return Arrays.copyOfRange(record, 27, 39); }
    byte[] header() { return Arrays.copyOf(record, HEADER_BYTES); }
    byte[] wrappedRootAndTag() { return Arrays.copyOfRange(record, 39, RECORD_BYTES); }
}
