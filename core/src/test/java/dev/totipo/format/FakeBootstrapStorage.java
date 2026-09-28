package dev.totipo.format;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

/** Strict contract-outcome model only, NOT a crash-durable backend. */
final class FakeBootstrapStorage implements VaultBootstrapReplacementStorage {
    enum Fault { NONE, STAGE, STAGED_READ, INSTALL, INSTALL_AFTER_PUBLICATION, CANONICAL_READ, CLEANUP }
    byte[] canonical, stagedSubstitution, installedSubstitution, collision, residue;
    Fault fault = Fault.NONE;
    boolean closed, stagedClosed, installed;
    int stages, reads;
    Runnable beforeStage = () -> {}, beforeInstall = () -> {}, beforeCanonical = () -> {};
    final List<String> events = new ArrayList<>();
    private void requireOpen() throws IOException { if (closed) { throw new IOException("Closed"); } }
    @Override public InputStream openCanonicalRead() throws IOException {
        requireOpen(); reads++; events.add("canonical"); beforeCanonical.run();
        if (fault == Fault.CANONICAL_READ && installed) { throw new IOException("Injected read"); }
        return canonical == null ? null : new ByteArrayInputStream(canonical.clone());
    }
    @Override public StagedBootstrap stageInitial(byte[] candidate) throws IOException {
        requireOpen(); beforeStage.run(); stages++; events.add("stage");
        if (fault == Fault.STAGE) { throw new IOException("Injected stage"); }
        byte[] exact = candidate.clone();
        byte[] completed = stagedSubstitution == null ? exact : stagedSubstitution.clone();
        residue = completed.clone();
        return new StagedBootstrap() {
            boolean handleClosed, attempted;
            private void usable() throws IOException {
                requireOpen(); if (handleClosed) { throw new IOException("Staged handle closed"); }
            }
            @Override public InputStream openRead() throws IOException {
                usable(); events.add("staged-read");
                if (fault == Fault.STAGED_READ) { throw new IOException("Injected staged read"); }
                return new ByteArrayInputStream(completed.clone());
            }
            @Override public void installInitialDurably() throws IOException {
                usable(); if (attempted) { throw new IOException("Install already attempted"); }
                attempted = true; beforeInstall.run(); events.add("install");
                if (collision != null) { canonical = collision.clone(); }
                if (canonical != null || fault == Fault.INSTALL) { throw new IOException("Install failed"); }
                canonical = installedSubstitution == null ? completed.clone() : installedSubstitution.clone();
                installed = true;
                if (fault == Fault.INSTALL_AFTER_PUBLICATION) { throw new IOException("Ambiguous install"); }
            }
            @Override public void close() throws IOException {
                handleClosed = true; stagedClosed = true; events.add("cleanup");
                if (fault == Fault.CLEANUP) { throw new IOException("Injected cleanup"); }
                residue = null;
            }
        };
    }
    @Override public void close() { closed = true; }

    @Override public StagedReplacement stageReplacement(byte[] candidate) throws IOException {
        requireOpen(); beforeStage.run(); stages++; events.add("replacement-stage");
        if (fault == Fault.STAGE) { throw new IOException("Injected stage"); }
        byte[] completed = (stagedSubstitution == null ? candidate : stagedSubstitution).clone();
        residue = completed.clone();
        return new StagedReplacement() {
            boolean handleClosed, attempted;
            private void usable() throws IOException {
                requireOpen(); if (handleClosed) { throw new IOException("Replacement closed"); }
            }
            @Override public InputStream openRead() throws IOException {
                usable(); events.add("replacement-read");
                if (fault == Fault.STAGED_READ) { throw new IOException("Injected read"); }
                return new ByteArrayInputStream(completed.clone());
            }
            @Override public void replaceCanonicalDurably() throws IOException {
                usable(); if (attempted) { throw new IOException("Replacement already attempted"); }
                attempted = true; beforeInstall.run(); events.add("replace");
                if (collision != null) { canonical = collision.clone(); }
                if (canonical == null || fault == Fault.INSTALL) { throw new IOException("Replacement failed"); }
                canonical = completed.clone(); // Single atomic model switch, no partial representation.
                installed = true;
                if (fault == Fault.INSTALL_AFTER_PUBLICATION) { throw new IOException("Ambiguous replacement"); }
                if (installedSubstitution != null) { canonical = installedSubstitution.clone(); }
            }
            @Override public void close() throws IOException {
                handleClosed = true; stagedClosed = true; events.add("cleanup");
                if (fault == Fault.CLEANUP) { throw new IOException("Injected cleanup"); }
                residue = null;
            }
        };
    }
}
