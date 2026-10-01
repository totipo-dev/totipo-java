package dev.totipo.storage.nio;

import dev.totipo.format.DiscoverySource;
import dev.totipo.format.ObjectId;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Direct-child observation of the configured durable store. Candidate bytes are hostile.
 * Namespace and enumeration issues are diagnostics only; they establish no operation gate. */
public final class NioDiscoverySource implements DiscoverySource {
    private final Path root;
    public NioDiscoverySource(Path root) {
        this.root = Objects.requireNonNull(root);
        if (!root.isAbsolute()) throw new IllegalArgumentException("ABSOLUTE_PATH_REQUIRED");
    }
    @Override public Snapshot snapshot() throws IOException {
        if (!Files.readAttributes(root, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isDirectory())
            return new Snapshot(List.of(), SnapshotIssue.UNSAFE_NAMESPACE);
        var scan = NioObjectScan.scan(root, new NioObjectScan.Operations());
        var candidates = new ArrayList<Candidate>();
        for (var entry : scan.entries()) {
            if (entry.kind() != dev.totipo.spi.EntryKind.REGULAR) continue;
            ObjectId id;
            try { id = ObjectId.fromFilename(entry.name().value()); }
            catch (IllegalArgumentException ignored) { continue; }
            candidates.add(new Candidate(id, () -> {
                Path directory = NioObjectScan.namespace(root);
                if (directory == null) throw new NoSuchFileException("objects-v1");
                Path path = NioFiles.findExactDirectChild(directory, entry.name().value())
                        .orElseThrow(() -> new NoSuchFileException(entry.name().value()));
                NioFiles.regular(path);
                return Files.newByteChannel(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
            }));
        }
        var issue = scan instanceof dev.totipo.spi.ObjectScan.Incomplete incomplete
                ? (incomplete.reason() == dev.totipo.spi.StoreFailure.UNSAFE_NAMESPACE
                    ? SnapshotIssue.UNSAFE_NAMESPACE : SnapshotIssue.ENUMERATION_UNAVAILABLE)
                : SnapshotIssue.NONE;
        return new Snapshot(candidates, issue);
    }
}
