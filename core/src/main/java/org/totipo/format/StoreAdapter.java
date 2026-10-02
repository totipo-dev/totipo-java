package org.totipo.format;

import org.totipo.spi.*;
import java.io.*;
import java.nio.channels.Channels;
import java.util.ArrayList;
import java.util.Objects;

/** Core-only translation to the proven protocol machinery. Owns one transferred store. */
final class StoreAdapter implements VaultBootstrapReplacementStorage, DiscoverySource, V1ObjectPublicationStore {
    private final TotipoStore store;
    private boolean closed;
    StoreAdapter(TotipoStore store) { this.store = Objects.requireNonNull(store); }

    @Override public InputStream openCanonicalRead() throws IOException {
        return stream(store.readVault(VaultBootstrap.RECORD_BYTES), VaultBootstrap.RECORD_BYTES);
    }
    /** Size-only failures cannot contain valid protocol records. Preserve invalid-size taxonomy
     * through the legacy bounded readers without manufacturing a valid record. */
    private static InputStream stream(BoundedRead read, int expected) throws IOException {
        if (read instanceof BoundedRead.Present present) {
            byte[] bytes = present.bytes();
            if (bytes.length != expected) throw new IOException("Provider violated exact-size contract");
            return new ByteArrayInputStream(bytes);
        }
        if (read instanceof BoundedRead.Absent) return null;
        if (read instanceof BoundedRead.Undersized shortRead) {
            if (shortRead.observedLength() >= expected) throw new IOException("Invalid short-read length");
            return new ByteArrayInputStream(new byte[(int)shortRead.observedLength()]);
        }
        if (read instanceof BoundedRead.Oversized) return new ByteArrayInputStream(new byte[expected + 1]);
        throw new IOException("Storage observation unavailable");
    }
    @Override public Snapshot snapshot() {
        var scan = store.scanObjects();
        var candidates = new ArrayList<Candidate>();
        for (var entry : scan.entries()) {
            // Protocol filename interpretation is exclusively core behavior.
            ObjectId id;
            try { id = ObjectId.fromFilename(entry.name().value()); }
            catch (IllegalArgumentException ignored) { continue; }
            // Scan kind/length are observations only; every canonical name gets a fresh read.
            candidates.add(new Candidate(id, () -> {
                var stream = stream(store.readObject(entry.name(), 1024), 1024);
                if (stream == null) throw new IOException("Object disappeared");
                return Channels.newChannel(stream);
            }));
        }
        var issue = scan instanceof ObjectScan.Incomplete incomplete
                ? (incomplete.reason() == StoreFailure.UNSAFE_NAMESPACE
                    ? SnapshotIssue.UNSAFE_NAMESPACE : SnapshotIssue.ENUMERATION_UNAVAILABLE)
                : SnapshotIssue.NONE;
        return new Snapshot(candidates, issue);
    }
    @Override public PublicationResult publish(ObjectId id, byte[] bytes) throws IOException {
        var result = store.publishObject(new ObjectName(id.filename()), bytes);
        if (result instanceof ObjectWrite.Written) return PublicationResult.PUBLISHED_NEW;
        if (result instanceof ObjectWrite.AlreadyPresentExact) return PublicationResult.ALREADY_PRESENT_EXACT;
        // Existing application publication policy remains conservatively monotonic after entry.
        throw new IOException("Publication not acknowledged: " + result);
    }
    private Stage stage(byte[] bytes) throws IOException {
        var prepared = store.prepareVault(bytes);
        if (prepared instanceof VaultPrepare.Prepared ready) return new Stage(ready.vault());
        throw new IOException("Staging unavailable");
    }
    @Override public StagedBootstrap stageInitial(byte[] bytes) throws IOException { return stage(bytes); }
    @Override public StagedReplacement stageReplacement(byte[] bytes) throws IOException { return stage(bytes); }
    /** Positive no-mutation evidence, unlike an arbitrary provider exception after call entry. */
    static final class DefiniteFailure extends IOException {
        private static final long serialVersionUID = 1L;
        final boolean alreadyPresent;
        DefiniteFailure(boolean alreadyPresent) { this.alreadyPresent = alreadyPresent; }
    }
    private record Stage(PreparedVault vault) implements StagedBootstrap, StagedReplacement {
        @Override public InputStream openRead() throws IOException {
            return stream(vault.readBack(VaultBootstrap.RECORD_BYTES), VaultBootstrap.RECORD_BYTES);
        }
        @Override public void installInitialDurably() throws IOException {
            var result = vault.installCanonicalIfAbsent();
            if (result instanceof VaultInstall.Installed) return;
            if (result instanceof VaultInstall.AlreadyPresent) throw new DefiniteFailure(true);
            if (result instanceof VaultInstall.Failed) throw new DefiniteFailure(false);
            throw new IOException("Installation not acknowledged");
        }
        @Override public void replaceCanonicalDurably() throws IOException {
            var result = vault.replaceCanonical();
            if (result instanceof VaultReplace.Replaced) return;
            if (result instanceof VaultReplace.Failed) throw new DefiniteFailure(false);
            throw new IOException("Replacement not acknowledged");
        }
        @Override public void close() { vault.close(); }
    }
    @Override public void close() {
        if (closed) return;
        closed = true; store.close();
    }
}
