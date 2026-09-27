package dev.totipo.format;

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/**
 * Storage trust boundary. Freeze accepted direct, no-follow regular-file names before
 * returning. Openers must provide stable, bounded-read-capable handles without following
 * links, escaping the bound namespace, or opening hostile special files. If this cannot
 * be guaranteed, throw UnsupportedOperationException before attempting an open.
 * The caller owns the source's lifetime (including any retained directory bindings).
 */
interface DiscoverySource {
    Snapshot snapshot() throws IOException;

    @FunctionalInterface
    interface Opener { ReadableByteChannel open() throws IOException; }

    record Candidate(ObjectId id, Opener opener) {
        public Candidate { Objects.requireNonNull(id); Objects.requireNonNull(opener); }
        @Override public String toString() { return "Candidate[" + id.filename() + "]"; }
    }

    enum SnapshotIssue { NONE, ENUMERATION_UNAVAILABLE, UNSUPPORTED_DIRECTORY_ACCESS, UNSAFE_NAMESPACE }

    record Snapshot(List<Candidate> candidates, SnapshotIssue issue) {
        public Snapshot {
            Objects.requireNonNull(issue);
            candidates = candidates.stream().sorted(Comparator.comparing(c -> c.id().filename())).toList();
            var ids = new HashSet<ObjectId>();
            for (var c : candidates) {
                if (!ids.add(c.id())) { throw new IllegalArgumentException("Duplicate candidate name"); }
            }
        }
        boolean complete() { return issue == SnapshotIssue.NONE; }
    }
}
