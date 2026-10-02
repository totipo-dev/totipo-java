package org.totipo.spi;

import java.util.Objects;

/** Preparation never changes canonical vault. Failed may leave abandoned temporary artifacts. */
public sealed interface VaultPrepare {
    record Prepared(PreparedVault vault) implements VaultPrepare {
        public Prepared { Objects.requireNonNull(vault); }
    }
    record Failed(StoreFailure reason) implements VaultPrepare {
        public Failed { Objects.requireNonNull(reason); }
    }
}
