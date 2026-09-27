package dev.totipo.format;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DiscoveryLifecycleTest {
    @Test void successfulAndFailedReadsCloseExactlyOnce() throws Exception {
        var fixture = DiscoveryFixtures.fixture(DiscoveryFixtures.TOKEN);
        for (boolean failRead : List.of(false, true)) {
            var closes = new AtomicInteger();
            var candidate = new DiscoverySource.Candidate(fixture.id(), () -> {
                if (failRead) { throw new IOException("test"); }
                return Channels.newChannel(new ByteArrayInputStream(fixture.bytes()));
            });
            var snapshot = new DiscoverySource.Snapshot(List.of(candidate), DiscoverySource.SnapshotIssue.NONE, closes::incrementAndGet);
            var result = DiscoveryFixtures.run(() -> snapshot, fixture.root(), DurableKnowledgeState.establishedEmpty());
            assertEquals(failRead ? DiscoveryState.PROCESSING_INCOMPLETE : DiscoveryState.READY, result.discoveryState());
            snapshot.close(); assertEquals(1, closes.get());
        }
    }
    @Test void classifierExceptionClosesSnapshot() throws Exception {
        var fixture = DiscoveryFixtures.fixture(DiscoveryFixtures.TOKEN); var closes = new AtomicInteger();
        var source = new DiscoveryFixtures(); source.put(fixture);
        var snapshot = new DiscoverySource.Snapshot(source.snapshot().candidates(), DiscoverySource.SnapshotIssue.NONE, closes::incrementAndGet);
        assertThrows(IllegalStateException.class, () -> DiscoveryCoordinator.discover(() -> snapshot, fixture.root(),
                DurableKnowledgeState.establishedEmpty(), o -> DurableKnowledgeState.PersistenceResult.COMMITTED,
                new ObjectDiscovery((name, bytes, root) -> { throw new IllegalStateException("test classifier"); })));
        assertEquals(1, closes.get());
    }
    @Test void commitFailuresAndUnexpectedExceptionsCloseSnapshot() throws Exception {
        var fixture = DiscoveryFixtures.fixture(DiscoveryFixtures.TOKEN);
        for (int mode = 0; mode < 3; mode++) {
            var closes = new AtomicInteger(); var source = new DiscoveryFixtures(); source.put(fixture);
            var snapshot = new DiscoverySource.Snapshot(source.snapshot().candidates(), DiscoverySource.SnapshotIssue.NONE, closes::incrementAndGet);
            int failureMode = mode;
            DiscoveryCoordinator.Committer committer = o -> {
                if (failureMode == 0) { return DurableKnowledgeState.PersistenceResult.FAILED; }
                if (failureMode == 1) { throw new IOException("test"); }
                throw new IllegalStateException("test");
            };
            if (mode == 2) {
                assertThrows(IllegalStateException.class, () -> DiscoveryCoordinator.discover(() -> snapshot,
                        fixture.root(), DurableKnowledgeState.establishedEmpty(), committer));
            } else {
                assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, DiscoveryCoordinator.discover(() -> snapshot,
                        fixture.root(), DurableKnowledgeState.establishedEmpty(), committer).discoveryState());
            }
            assertEquals(1, closes.get());
        }
    }
    @Test void closeFailureConservativelyPreventsReadyWithoutRetry() throws Exception {
        var closes = new AtomicInteger();
        var snapshot = new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.NONE,
                () -> { closes.incrementAndGet(); throw new IOException("test close"); });
        var result = DiscoveryFixtures.run(() -> snapshot, new byte[32], DurableKnowledgeState.establishedEmpty());
        assertFalse(result.resourceComplete()); assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        snapshot.close(); assertEquals(1, closes.get());
    }
}
