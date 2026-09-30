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
        var exact = NioFiles.findExactDirectChild(root, "objects-v1");
        if (exact.isEmpty()) return new Snapshot(List.of(), SnapshotIssue.NONE);
        Path directory = exact.get();
        try {
            if (!Files.readAttributes(directory, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isDirectory())
                return new Snapshot(List.of(), SnapshotIssue.UNSAFE_NAMESPACE);
        } catch (NoSuchFileException absent) { return new Snapshot(List.of(), SnapshotIssue.NONE); }
        var candidates = new ArrayList<Candidate>();
        var issue = SnapshotIssue.NONE;
        try (var entries = Files.newDirectoryStream(directory)) {
            for (Path entry : entries) {
                ObjectId id;
                try { id = ObjectId.fromFilename(entry.getFileName().toString()); }
                catch (IllegalArgumentException ignored) { continue; }
                try {
                    if (!Files.readAttributes(entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isRegularFile()) continue;
                    candidates.add(new Candidate(id, () -> {
                        NioFiles.regular(entry);
                        return Files.newByteChannel(entry, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
                    }));
                } catch (IOException e) { issue = SnapshotIssue.ENUMERATION_UNAVAILABLE; }
            }
        } catch (DirectoryIteratorException | IOException | SecurityException e) {
            issue = SnapshotIssue.ENUMERATION_UNAVAILABLE;
        }
        return new Snapshot(candidates, issue);
    }
}
