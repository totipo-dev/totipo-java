package org.totipo.spi;

import java.util.Objects;

/** Success includes configured durability acknowledgement. Failed proves this invocation did not change the target; Uncertain means mutation may have occurred without acknowledgement. */
public sealed interface VaultInstall {
    record Installed() implements VaultInstall {}
    record AlreadyPresent() implements VaultInstall {}
    record Failed(StoreFailure reason) implements VaultInstall {
        public Failed { Objects.requireNonNull(reason); }
    }
    record Uncertain(StoreFailure reason) implements VaultInstall {
        public Uncertain { Objects.requireNonNull(reason); }
    }
}
