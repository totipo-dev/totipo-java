package org.totipo.format;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

/** Deterministic opaque-storage faults, never a second lifecycle implementation. */
final class VaultTestStore implements VaultBootstrapReplacementStorage {
    interface Action { void run() throws IOException; }
    byte[] canonical;
    byte[] staged;
    boolean unreadable, durable = true, installOnFailure, corruptStage, closeFailure;
    int reads, stages, installs, replacements, closes;
    Action beforeRead = () -> {}, beforeStage = () -> {}, beforeInstall = () -> {};
    java.util.function.UnaryOperator<byte[]> stagedTransform = bytes -> bytes;
    final List<String> events = new ArrayList<>();
    final List<byte[]> callerArrays = new ArrayList<>();

    @Override public InputStream openCanonicalRead() throws IOException {
        reads++; events.add("read"); beforeRead.run();
        if (unreadable) throw new IOException("Injected unavailable canonical");
        return canonical == null ? null : new ByteArrayInputStream(canonical.clone());
    }
    private Stage stage(byte[] candidate) throws IOException {
        stages++; events.add("stage"); beforeStage.run(); callerArrays.add(candidate);
        staged = stagedTransform.apply(candidate.clone());
        if (corruptStage) staged[86] ^= 1;
        return new Stage(staged.clone());
    }
    @Override public StagedBootstrap stageInitial(byte[] candidate) throws IOException { return stage(candidate); }
    @Override public StagedReplacement stageReplacement(byte[] candidate) throws IOException { return stage(candidate); }
    @Override public void close() {}
    private final class Stage implements StagedBootstrap, StagedReplacement {
        private final byte[] bytes;
        private boolean attempted;
        Stage(byte[] bytes) { this.bytes = bytes; }
        @Override public InputStream openRead() { events.add("stage-read"); return new ByteArrayInputStream(bytes.clone()); }
        private void install(boolean replacement) throws IOException {
            if (attempted) throw new AssertionError("Automatic retry");
            attempted = true;
            beforeInstall.run();
            if (replacement) { replacements++; events.add("replace"); }
            else { installs++; events.add("install"); if (canonical != null) throw new IOException("Already exists"); }
            if (durable || installOnFailure) canonical = bytes.clone();
            if (!durable) throw new IOException("Injected ambiguous acknowledgement");
        }
        @Override public void installInitialDurably() throws IOException { install(false); }
        @Override public void replaceCanonicalDurably() throws IOException { install(true); }
        @Override public void close() throws IOException {
            closes++; Arrays.fill(bytes, (byte) 0);
            if (closeFailure) throw new IOException("Injected cleanup failure");
        }
    }
}
