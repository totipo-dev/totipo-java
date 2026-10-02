package org.totipo.format;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import static org.junit.jupiter.api.Assertions.*;

class DiscoverySourceTest {
    @Test @Timeout(30)
    void collidingDistinctIdsSortDeterministicallyAndDuplicatesStillFail() throws Exception {
        var candidates = new ArrayList<DiscoverySource.Candidate>();
        Integer hash = null;
        for (int mask = 0; mask < 16_384; mask++) {
            byte[] bytes = new byte[32];
            for (int pair = 0; pair < 16; pair++) {
                boolean bit = (mask & (1 << pair)) != 0;
                bytes[2 * pair] = (byte) (bit ? 1 : 0);
                bytes[2 * pair + 1] = (byte) (bit ? 0 : 31);
            }
            var id = new ObjectId(bytes);
            if (hash == null) hash = Arrays.hashCode(bytes);
            assertEquals(hash.intValue(), Arrays.hashCode(bytes));
            assertEquals(hash.intValue(), id.hashCode());
            candidates.add(new DiscoverySource.Candidate(id, () -> { throw new AssertionError("Must not read"); }));
        }
        Collections.shuffle(candidates, new Random(17));
        try (var first = new DiscoverySource.Snapshot(candidates, DiscoverySource.SnapshotIssue.NONE)) {
            assertEquals(16_384, first.candidates().size());
            for (int i = 1; i < first.candidates().size(); i++) {
                var previous = first.candidates().get(i - 1).id();
                var current = first.candidates().get(i).id();
                assertNotEquals(previous, current);
                assertTrue(previous.filename().compareTo(current.filename()) < 0);
            }
            Collections.reverse(candidates);
            try (var second = new DiscoverySource.Snapshot(candidates, DiscoverySource.SnapshotIssue.NONE)) {
                assertEquals(first.candidates(), second.candidates());
            }
        }
        candidates.add(candidates.get(123));
        assertThrows(IllegalArgumentException.class,
                () -> new DiscoverySource.Snapshot(candidates, DiscoverySource.SnapshotIssue.NONE));
    }
}
