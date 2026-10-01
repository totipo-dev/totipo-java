package dev.totipo.spi;

import java.util.Objects;

/** Success includes configured durability acknowledgement. Failed proves this invocation did not change the target; Uncertain means mutation may have occurred without acknowledgement. */
public sealed interface VaultReplace {
    record Replaced() implements VaultReplace {}
    record Failed(StoreFailure reason) implements VaultReplace {
        public Failed { Objects.requireNonNull(reason); }
    }
    record Uncertain(StoreFailure reason) implements VaultReplace {
        public Uncertain { Objects.requireNonNull(reason); }
    }
}
