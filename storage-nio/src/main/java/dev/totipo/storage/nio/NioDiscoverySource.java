package dev.totipo.storage.nio;

import dev.totipo.format.DiscoverySource;
import dev.totipo.format.ObjectId;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Direct-child discovery under r14's trusted local execution environment.
 * Synchronized bytes remain untrusted. Core reads at most 1025 bytes and authenticates
 * every candidate. Ordinary read/disappearance failures make the pass incomplete. */
public final class NioDiscoverySource implements DiscoverySource {
    private final Path root;
    public NioDiscoverySource(Path root) {
        this.root = Objects.requireNonNull(root);
        if (!root.isAbsolute()) throw new IllegalArgumentException("ABSOLUTE_PATH_REQUIRED");
    }
    @Override public Snapshot snapshot() throws IOException {
        if (!Files.readAttributes(root, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isDirectory())
            return new Snapshot(List.of(), SnapshotIssue.UNSAFE_NAMESPACE);
        Path directory = root.resolve("objects-v1");
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
