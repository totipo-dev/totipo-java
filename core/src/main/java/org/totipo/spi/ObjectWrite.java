package org.totipo.spi;

import java.util.Objects;

/** Success includes configured durability acknowledgement. Failed proves this invocation did not change the target; Uncertain means mutation may have occurred without acknowledgement. */
public sealed interface ObjectWrite {
    record Written() implements ObjectWrite {}
    record AlreadyPresentExact() implements ObjectWrite {}
    record ExistingDifferent() implements ObjectWrite {}
    record Failed(StoreFailure reason) implements ObjectWrite {
        public Failed { Objects.requireNonNull(reason); }
    }
    record Uncertain(StoreFailure reason) implements ObjectWrite {
        public Uncertain { Objects.requireNonNull(reason); }
    }
}
