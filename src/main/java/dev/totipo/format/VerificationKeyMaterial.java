package dev.totipo.format;

import java.util.Arrays;
import java.util.List;

/** Immutable current inputs, with no storage-origin or DEVICE-provenance policy. */
final class VerificationKeyMaterial {
    /** The claimed identity is untrusted metadata; evaluation uses only the exact key bytes. */
    record Candidate(byte[] claimedDeviceId, byte[] publicKey) {
        Candidate {
            if (claimedDeviceId.length != 32 || publicKey.length != 65) {
                throw new IllegalArgumentException("Invalid candidate structural width");
            }
            claimedDeviceId = claimedDeviceId.clone();
            publicKey = publicKey.clone();
        }
        @Override public byte[] claimedDeviceId() { return claimedDeviceId.clone(); }
        @Override public byte[] publicKey() { return publicKey.clone(); }
    }

    private final List<Candidate> candidates;
    private final boolean temporarilyUnavailable;

    private VerificationKeyMaterial(List<Candidate> candidates, boolean temporarilyUnavailable) {
        this.candidates = List.copyOf(candidates);
        this.temporarilyUnavailable = temporarilyUnavailable;
    }

    static VerificationKeyMaterial available(List<Candidate> candidates) {
        return new VerificationKeyMaterial(candidates, false);
    }

    static VerificationKeyMaterial keys(byte[]... keys) {
        return available(Arrays.stream(keys).map(k -> new Candidate(P256.deviceId(k), k)).toList());
    }

    /** Actual local inability to obtain material or perform verification, including DEVICE verification. */
    static VerificationKeyMaterial temporarilyUnavailable() {
        return new VerificationKeyMaterial(List.of(), true);
    }

    List<Candidate> candidates() { return candidates; }
    boolean isTemporarilyUnavailable() { return temporarilyUnavailable; }
}
