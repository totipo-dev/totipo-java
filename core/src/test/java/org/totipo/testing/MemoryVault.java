package org.totipo.testing;

import org.totipo.*;
import org.totipo.format.*;
import java.io.*;
import java.nio.channels.Channels;
import java.util.*;
import java.util.concurrent.*;

/** Provider fault fixture; tests consuming it use only the application-facing API. */
public final class MemoryVault {
    public final Map<String, byte[]> objects = new ConcurrentHashMap<>();
    public volatile byte[] bootstrap;
    public volatile boolean observationUnavailable, readUnavailable, failBeforeStage, failReplacement, staleReplacement;
    public volatile int publicationMode; // 0 acknowledged, 1 throws before write, 2 writes then throws
    public volatile int writes, scans, publications;
    public volatile RuntimeException fatalObservation;
    public volatile boolean publicationClosed, bootstrapClosed;
    public volatile int stagedTrailingBytes, initialInstallAttempts, replacementAttempts;
    public volatile int bootstrapReadLimit = Integer.MAX_VALUE, maxBootstrapRead;
    public Runnable afterReplacementStage = () -> {};
    public volatile CountDownLatch entered, proceed, scanEntered, scanProceed;
    public final List<String> attemptedIds = new CopyOnWriteArrayList<>();
    public final List<byte[]> attemptedBytes = new CopyOnWriteArrayList<>();
    public VaultSession create() {
        return ((CreateVaultResult.Created) createResult("password".toCharArray())).session();
    }
    public CreateVaultResult createResult(char[] password) {
        return ApplicationVaults.create(new Bootstrap(), this::snapshot, new Publication(), password);
    }
    public VaultSession open() { return ((OpenResult.Opened) openResult("password".toCharArray())).session(); }
    public OpenResult openResult(char[] password) {
        return ApplicationVaults.open(new Bootstrap(), this::snapshot, new Publication(), password);
    }
    private DiscoverySource.Snapshot snapshot() throws IOException {
        scans++;
        if (scanEntered != null) { scanEntered.countDown(); await(scanProceed); }
        if (fatalObservation != null) throw fatalObservation;
        if (observationUnavailable) throw new IOException("Unavailable observation");
        var candidates = new ArrayList<DiscoverySource.Candidate>();
        objects.forEach((id, bytes) -> candidates.add(new DiscoverySource.Candidate(ObjectId.fromFilename(id),
                () -> Channels.newChannel(new ByteArrayInputStream(bytes)))));
        return new DiscoverySource.Snapshot(candidates, DiscoverySource.SnapshotIssue.NONE);
    }
    private final class Publication implements V1ObjectPublicationStore {
        @Override public PublicationResult publish(ObjectId id, byte[] bytes) throws IOException {
            publications++; attemptedIds.add(id.filename()); attemptedBytes.add(bytes.clone());
            if (entered != null) { entered.countDown(); await(proceed); }
            if (publicationMode == 1) throw new IOException("Provider unavailable");
            var previous = objects.putIfAbsent(id.filename(), bytes.clone());
            if (previous == null) writes++;
            else if (!Arrays.equals(previous, bytes)) throw new IOException("Collision");
            if (publicationMode == 2) throw new IOException("Acknowledgement lost");
            return previous == null ? PublicationResult.PUBLISHED_NEW : PublicationResult.ALREADY_PRESENT_EXACT;
        }
        @Override public void close() { publicationClosed = true; }
    }
    private final class Bootstrap implements VaultBootstrapReplacementStorage {
        @Override public InputStream openCanonicalRead() throws IOException {
            if (readUnavailable) throw new IOException("Unavailable bootstrap");
            return bootstrap == null ? null : bootstrapStream(bootstrap);
        }
        @Override public StagedBootstrap stageInitial(byte[] bytes) throws IOException {
            if (failBeforeStage) throw new IOException("Stage unavailable");
            return new Stage(bytes);
        }
        @Override public StagedReplacement stageReplacement(byte[] bytes) throws IOException {
            if (failBeforeStage) throw new IOException("Stage unavailable");
            if (staleReplacement) bootstrap = bootstrap.clone();
            if (staleReplacement) bootstrap[bootstrap.length - 1] ^= 1;
            afterReplacementStage.run();
            return new Stage(bytes);
        }
        @Override public void close() { bootstrapClosed = true; }
    }
    private final class Stage implements VaultBootstrapStorage.StagedBootstrap, VaultBootstrapReplacementStorage.StagedReplacement {
        private final byte[] bytes;
        Stage(byte[] bytes) { this.bytes = bytes.clone(); }
        @Override public InputStream openRead() { return bootstrapStream(Arrays.copyOf(bytes, bytes.length + stagedTrailingBytes)); }
        @Override public void installInitialDurably() throws IOException {
            initialInstallAttempts++;
            if (bootstrap != null) throw new IOException("Exists");
            bootstrap = bytes.clone();
            if (failReplacement) throw new IOException("Lost acknowledgement");
        }
        @Override public void replaceCanonicalDurably() throws IOException {
            replacementAttempts++;
            bootstrap = bytes.clone();
            if (failReplacement) throw new IOException("Lost acknowledgement");
        }
        @Override public void close() { }
    }
    private InputStream bootstrapStream(byte[] bytes) {
        return new InputStream() {
            private final ByteArrayInputStream source = new ByteArrayInputStream(bytes);
            private int consumed;
            private void count(int read) {
                if (read > 0) consumed += read;
                maxBootstrapRead = Math.max(maxBootstrapRead, consumed);
                if (consumed > bootstrapReadLimit) throw new AssertionError("Unbounded bootstrap read");
            }
            @Override public int read() { int value = source.read(); count(value < 0 ? 0 : 1); return value; }
            @Override public int read(byte[] target, int offset, int length) {
                int read = source.read(target, offset, length); count(read); return read;
            }
        };
    }
    private static void await(CountDownLatch latch) throws IOException {
        if (latch == null) return;
        try { if (!latch.await(10, TimeUnit.SECONDS)) throw new IOException("Fixture timeout"); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
    }
}
