package org.totipo;

import java.util.Objects;
public sealed interface OpenResult {
    record Opened(VaultSession session) implements OpenResult {
        public Opened { Objects.requireNonNull(session); }
    }
    record Absent() implements OpenResult { }
    record Unavailable() implements OpenResult { }
    record InvalidVault() implements OpenResult { }
    record AuthenticationFailed() implements OpenResult { }
}

