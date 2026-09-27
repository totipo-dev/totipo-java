package dev.totipo.fs.linux;

import dev.totipo.format.DiscoverySource;
import dev.totipo.format.ObjectId;

import java.io.IOException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.SecureDirectoryStream;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Read-only JDK adapter with explicit §50 capability gaps. The application must
 * securely bind the configured root path and its ancestors for snapshot(); hostile
 * entries begin beneath it. No root canonicalization or relocation occurs here.
 *
 * Public JDK 17 lacks atomic regular-only open and nonblocking directory-only open
 * guarantees. Even UnixSecureDirectoryStream.newDirectoryStream uses openat with
 * O_RDONLY (and O_NOFOLLOW), then fdopendir: a substituted FIFO can block BEFORE
 * directory validation. Thus this path adapter never opens an existing namespace.
 * A securely prebound namespace can be enumerated using boundNamespace(), but every
 * accepted candidate remains UNAVAILABLE until a secure platform source can open it.
 */
public final class NioDiscoverySource implements DiscoverySource {
    private final Path configuredRoot;

    public NioDiscoverySource(Path configuredRoot) { this.configuredRoot = Objects.requireNonNull(configuredRoot); }

    @Override public Snapshot snapshot() throws IOException {
        // Reject an explicitly symlinked/non-directory configured root. Its ancestors
        // and the check/open interval are the application's external binding prerequisite.
        var configured = Files.readAttributes(configuredRoot, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!configured.isDirectory() || configured.isSymbolicLink()) {
            return new Snapshot(List.of(), SnapshotIssue.UNSAFE_NAMESPACE);
        }
        try (var rootStream = Files.newDirectoryStream(configuredRoot)) {
            if (!(rootStream instanceof SecureDirectoryStream<Path> root)) {
                return new Snapshot(List.of(), SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS);
            }
            Path family = configuredRoot.getFileSystem().getPath("objects-v1");
            try {
                var attributes = root.getFileAttributeView(family, BasicFileAttributeView.class,
                        LinkOption.NOFOLLOW_LINKS).readAttributes();
                if (!attributes.isDirectory() || attributes.isSymbolicLink()) {
                    return new Snapshot(List.of(), SnapshotIssue.UNSAFE_NAMESPACE);
                }
            } catch (NoSuchFileException e) {
                // Relative no-follow lookup beneath the open readable root proved absence.
                return new Snapshot(List.of(), SnapshotIssue.NONE);
            }
            // Do not call newDirectoryStream here: pre-open type checks cannot close
            // its FIFO/device substitution race. Empty-looking is not proven empty.
            return new Snapshot(List.of(), SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS);
        }
    }

    /**
     * Capability boundary for a future secure platform directory opener. The caller
     * must supply the exact objects-v1 directory, safely opened beneath the configured
     * root without links/special-file side effects, and keep it open through snapshot.
     * One stream supports one pass (DirectoryStream permits only one iterator).
     * This does not attest safe candidate opening. Tests bind controlled directories.
     */
    public static DiscoverySource boundNamespace(SecureDirectoryStream<Path> directory) {
        Objects.requireNonNull(directory);
        return () -> enumerate(directory);
    }

    private static Snapshot enumerate(SecureDirectoryStream<Path> directory) {
        var candidates = new ArrayList<Candidate>();
        try {
            for (var entry : directory) {
                var name = entry.getFileName();
                ObjectId id;
                try { id = ObjectId.fromFilename(name.toString()); }
                catch (IllegalArgumentException e) { continue; }
                var attrs = directory.getFileAttributeView(name, BasicFileAttributeView.class,
                        LinkOption.NOFOLLOW_LINKS).readAttributes();
                if (!attrs.isRegularFile() || attrs.isSymbolicLink()) { continue; }
                candidates.add(new Candidate(id, () -> {
                    // NOFOLLOW_LINKS is not regular-only. Never open the candidate.
                    throw new UnsupportedOperationException("Atomic safe regular-file open unavailable");
                }));
            }
        } catch (DirectoryIteratorException | IOException | SecurityException e) {
            return new Snapshot(candidates, SnapshotIssue.ENUMERATION_UNAVAILABLE);
        }
        return new Snapshot(candidates, SnapshotIssue.NONE);
    }
}
