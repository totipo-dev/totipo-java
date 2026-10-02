package org.totipo.storage.nio;

import org.totipo.spi.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;

/** Shared exact-name enumeration and namespace observation. */
final class NioObjectScan {
    private NioObjectScan() {}
    static class Operations {
        DirectoryStream<Path> entries(Path directory) throws IOException { return Files.newDirectoryStream(directory); }
        BasicFileAttributes attributes(Path entry) throws IOException {
            return Files.readAttributes(entry, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        }
    }
    /** Null means positively absent; an alias lookup or non-directory is unsafe. */
    static Path namespace(Path root) throws IOException {
        NioFiles.directory(root);
        var exact = NioFiles.findExactDirectChild(root, "objects-v1");
        if (exact.isEmpty()) {
            // Lookup is used only to reject alias collisions, never to select an entry.
            try {
                Files.readAttributes(root.resolve("objects-v1"), BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            } catch (NoSuchFileException absent) { return null; }
            // A concurrent publisher may have created the exact namespace after enumeration.
            exact = NioFiles.findExactDirectChild(root, "objects-v1");
            if (exact.isEmpty()) throw new NioNamespace.Collision(root.resolve("objects-v1").toString());
        }
        NioFiles.directory(exact.get());
        return exact.get();
    }
    static StoreFailure reason(Exception failure) {
        return NioNamespace.failure(failure);
    }
    static ObjectScan scan(Path root, Operations scans) {
        var entries = new ArrayList<ObjectEntry>();
        StoreFailure issue = null;
        try {
            Path directory = namespace(root);
            if (directory == null) return new ObjectScan.Complete(List.of());
            try (var children = scans.entries(directory)) {
                for (var child : children) {
                    var name = new ObjectName(child.getFileName().toString());
                    EntryKind kind = EntryKind.UNKNOWN;
                    OptionalLong length = OptionalLong.empty();
                    try {
                        var attributes = scans.attributes(child);
                        kind = NioReads.kind(attributes);
                        if (kind == EntryKind.REGULAR) length = OptionalLong.of(attributes.size());
                    } catch (IOException | SecurityException | UnsupportedOperationException failure) {
                        issue = reason(failure);
                    }
                    entries.add(new ObjectEntry(name, kind, length));
                }
            }
        } catch (DirectoryIteratorException | IOException | SecurityException | UnsupportedOperationException failure) {
            issue = reason(failure);
        }
        // Stable sort preserves the first observation on an anomalous duplicate, without hashing hostile names.
        entries.sort(Comparator.comparing(entry -> entry.name().value()));
        var observed = new ArrayList<ObjectEntry>(entries.size());
        for (var entry : entries) {
            if (!observed.isEmpty() && observed.get(observed.size() - 1).name().value().equals(entry.name().value()))
                issue = StoreFailure.UNAVAILABLE;
            else observed.add(entry);
        }
        return issue == null ? new ObjectScan.Complete(observed) : new ObjectScan.Incomplete(observed, issue);
    }
}
