package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Executed coverage accounting, derived from the manifest rather than a case-ID allowlist. */
class Phase2ConformanceTest {
    @Test void everyImplementedCaseExecutesWithoutSkipping() throws Throwable {
        Set<String> implemented = Set.of("bootstrap", "crypto", "encoding", "metadata", "size", "totp");
        Set<String> deferred = Set.of("fold", "graph", "storage", "vault");
        var expected = new HashSet<String>();
        var executed = new HashSet<String>();
        var categories = new HashSet<String>();
        var trials = new TotpVectorTest().everyPinnedTrial();
        for (var vector : VectorCaseLoader.allCases()) {
            String category = vector.path().split("/")[1];
            categories.add(category);
            if (!implemented.contains(category)) {
                assertTrue(deferred.contains(category), "Unaccounted category: " + category);
                continue;
            }
            assertTrue(expected.add(vector.id()));
            try {
                switch (category) {
                    case "bootstrap" -> BootstrapVectorTest.check(vector);
                    case "crypto", "encoding", "metadata", "size" -> TokenVectorChecks.check(vector);
                    case "totp" -> {
                        // Execute the existing RFC trial assertions, retaining their original test cases.
                        var selected = trials.stream().filter(t -> t.getDisplayName().startsWith(vector.context() + " row ")).toList();
                        assertEquals(vector.data().field("totp").field("rows").array().size(), selected.size());
                        assertFalse(selected.isEmpty());
                        for (var trial : selected) trial.getExecutable().execute();
                    }
                    default -> fail("Implemented category has no consumer: " + category);
                }
            } catch (Throwable failure) {
                throw new AssertionError(vector.context(), failure);
            }
            assertTrue(executed.add(vector.id())); // Only recorded after all assertions return.
        }
        var all = new HashSet<>(implemented);
        all.addAll(deferred);
        assertEquals(all, categories);
        assertEquals(expected, executed);
        assertFalse(executed.isEmpty());
    }
}
