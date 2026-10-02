package org.totipo.spi;

import java.util.Objects;

/** Exact direct-child name in objects-v1. No protocol grammar, folding or normalization.
 * Providers reject names they cannot represent safely as one direct child. */
public record ObjectName(String value) {
    public ObjectName { Objects.requireNonNull(value); }
}
