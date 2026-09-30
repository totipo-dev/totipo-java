package dev.totipo.format;

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/** Storage observation boundary. Freeze exact direct-child names observed as regular
 * files without following final symlinks. Configured durable-store bytes are hostile: malformed,
 * stale, conflicting, missing, replayed, replaced or withheld. Local OS, filesystem,
 * mount/process namespace and same-privilege processes are trusted for baseline operation.
 * Readers remain bounded and cryptographically authenticated; ordinary I/O races
 * make observations unavailable/incomplete diagnostically; no global operation gate is implied.
 * The caller closes each snapshot and read handle. */
public interface DiscoverySource {
    Snapshot snapshot() throws IOException;

    @FunctionalInterface
    interface Opener { ReadableByteChannel open() throws IOException; }

    record Candidate(ObjectId id, Opener opener) {
        public Candidate { Objects.requireNonNull(id); Objects.requireNonNull(opener); }
        @Override public String toString() { return "Candidate[" + id.filename() + "]"; }
    }

    enum SnapshotIssue { NONE, ENUMERATION_UNAVAILABLE, UNSAFE_NAMESPACE }

    /** Frozen candidate set with an optional, thread-confined resource owner. Close once processing ends. */
    final class Snapshot implements java.io.Closeable {
        private final List<Candidate> candidates;
        private final SnapshotIssue issue;
        private final java.io.Closeable resource;
        private boolean closed;

        public Snapshot(List<Candidate> candidates, SnapshotIssue issue) {
            this(candidates, issue, () -> {});
        }

        public Snapshot(List<Candidate> candidates, SnapshotIssue issue, java.io.Closeable resource) {
            Objects.requireNonNull(issue);
            candidates = candidates.stream().sorted(Comparator.comparing(c -> c.id().filename())).toList();
            for (int i = 1; i < candidates.size(); i++) {
                if (candidates.get(i - 1).id().equals(candidates.get(i).id())) {
                    throw new IllegalArgumentException("Duplicate candidate name");
                }
            }
            this.candidates = candidates;
            this.issue = issue;
            this.resource = Objects.requireNonNull(resource);
        }
        public List<Candidate> candidates() { return candidates; }
        public SnapshotIssue issue() { return issue; }
        @Override public void close() throws IOException {
            if (!closed) { closed = true; resource.close(); }
        }
    }
}
