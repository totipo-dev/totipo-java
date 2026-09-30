package dev.totipo;

import java.util.Objects;
public sealed interface CreateVaultResult {
    record Created(VaultSession session) implements CreateVaultResult {
        public Created { Objects.requireNonNull(session); }
    }
    record AlreadyExists() implements CreateVaultResult { }
    record Failed() implements CreateVaultResult { }
    record Uncertain() implements CreateVaultResult { }
}

