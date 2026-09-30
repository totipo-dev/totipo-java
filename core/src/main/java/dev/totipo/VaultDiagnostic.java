package dev.totipo;

import java.util.Objects;
/** Local observation evidence, never a freshness or completeness assertion. */
public record VaultDiagnostic(String code) {
    public VaultDiagnostic { Objects.requireNonNull(code); }
}

