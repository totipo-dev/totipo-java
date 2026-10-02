package org.totipo.spi;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** One direct-child enumeration attempt. Complete means end reached, never an atomic snapshot.
 * Incomplete preserves observations but absence cannot establish completeness or freshness. */
public sealed interface ObjectScan {
    List<ObjectEntry> entries();
    record Complete(List<ObjectEntry> entries) implements ObjectScan {
        public Complete { entries = checked(entries); }
    }
    record Incomplete(List<ObjectEntry> entries, StoreFailure reason) implements ObjectScan {
        public Incomplete { entries = checked(entries); Objects.requireNonNull(reason); }
    }
    private static List<ObjectEntry> checked(List<ObjectEntry> entries) {
        var copy = new ArrayList<>(entries);
        // Observed names are hostile: compare strings, never hash them before authentication.
        copy.sort(Comparator.comparing(entry -> entry.name().value()));
        for (int i = 1; i < copy.size(); i++)
            if (copy.get(i - 1).name().value().equals(copy.get(i).name().value()))
                throw new IllegalArgumentException("Duplicate exact name");
        return List.copyOf(copy);
    }
}
