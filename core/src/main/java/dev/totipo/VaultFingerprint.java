package dev.totipo;

import java.util.Objects;
public record VaultFingerprint(String hex) {
    public VaultFingerprint { Objects.requireNonNull(hex); if (!hex.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("Fingerprint"); }
}

