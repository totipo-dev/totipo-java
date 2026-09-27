package dev.totipo.fs.linux;

import dev.totipo.format.DiscoverySource;
import dev.totipo.format.ObjectId;
import java.io.IOException;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Secure fixed-pass source for Linux amd64, JDK 25, libc statx, and usable procfs.
 * Requires explicit native-access permission. No automatic fallback is performed.
 * Roots must be absolute, standard UTF-8 representable default-filesystem paths;
 * native binding is checked against the Java path. Root ancestors and application
 * configuration remain trusted. Snapshots and channels are thread-confined and
 * must be closed. This source never mutates storage, including during probing.
 */
public final class LinuxSecureDiscoverySource implements DiscoverySource {
    public enum Capability {
        SUPPORTED, NOT_LINUX, UNSUPPORTED_ARCHITECTURE, NATIVE_ACCESS_DISABLED,
        REQUIRED_SYMBOL_UNAVAILABLE, PROCFS_UNAVAILABLE
    }
    private final Path root;
    private LinuxLibc libc;
    private Capability capability;
    // Narrow deterministic race/identity seams; no public configuration bypass.
    interface Hook { void run() throws IOException; }
    Hook beforeInspect = () -> {};
    Hook afterPin = () -> {};
    java.util.function.UnaryOperator<LinuxStatx> readableIdentity = value -> value;

    public LinuxSecureDiscoverySource(Path configuredRoot) {
        LinuxBoundFiles.path(configuredRoot);
        root = configuredRoot;
    }
    static Capability platform(String os, String arch) {
        if (!os.equals("Linux")) { return Capability.NOT_LINUX; }
        if (!arch.equals("amd64") && !arch.equals("x86_64")) { return Capability.UNSUPPORTED_ARCHITECTURE; }
        return Capability.SUPPORTED;
    }
    /** Lazily probes symbols and required procfd operations; failures never authorize discovery. */
    public synchronized Capability capability() {
        if (capability != null) { return capability; }
        capability = platform(System.getProperty("os.name"), System.getProperty("os.arch"));
        if (capability != Capability.SUPPORTED) { return capability; }
        if (!LinuxSecureDiscoverySource.class.getModule().isNativeAccessEnabled()) {
            return capability = Capability.NATIVE_ACCESS_DISABLED;
        }
        try { libc = new LinuxLibc(); }
        catch (IllegalCallerException e) { return capability = Capability.NATIVE_ACCESS_DISABLED; }
        catch (UnsatisfiedLinkError | UnsupportedOperationException e) {
            return capability = Capability.REQUIRED_SYMBOL_UNAVAILABLE;
        }
        try {
            // Existing JDK image file: no probe writes in the vault or elsewhere.
            try (var file = libc.open(Path.of(System.getProperty("java.home"), "lib", "modules").toString(), LinuxAbi.PIN)) {
                var identity = libc.stat(file);
                try (var readable = reopen(file, identity)) {
                    if (libc.read(readable, java.nio.ByteBuffer.allocate(1)) != 1) {
                        throw new IOException("PROC_READ_UNAVAILABLE");
                    }
                }
            }
            try (var dir = libc.open("/proc/self/fd", LinuxAbi.PIN | LinuxAbi.O_DIRECTORY)) {
                verifyDirectoryView(dir);
                try (var stream = Files.newDirectoryStream(dir.procPath())) { stream.iterator().hasNext(); }
            }
        } catch (IOException | SecurityException | DirectoryIteratorException e) {
            capability = Capability.PROCFS_UNAVAILABLE;
        }
        return capability;
    }
    private void verifyDirectoryView(LinuxFd dir) throws IOException {
        LinuxBoundFiles.verifyDirectoryView(libc, dir);
    }
    @Override public Snapshot snapshot() throws IOException {
        if (capability() != Capability.SUPPORTED) { return empty(SnapshotIssue.UNSUPPORTED_DIRECTORY_ACCESS); }
        LinuxFd family = null;
        try {
            try (var rootFd = LinuxBoundFiles.bindRoot(libc, root, LinuxAbi.PIN | LinuxAbi.O_DIRECTORY)) {
                try { family = libc.openAt(rootFd, "objects-v1", LinuxAbi.DIRECTORY); }
                catch (LinuxLibc.NativeFailure e) {
                    if (e.errno == LinuxAbi.ENOENT) { return empty(SnapshotIssue.NONE); }
                    throw e;
                }
            }
            verifyDirectoryView(family);
            var candidates = new ArrayList<Candidate>();
            var issue = SnapshotIssue.NONE;
            final LinuxFd bound = family;
            try (var stream = Files.newDirectoryStream(bound.procPath())) {
                for (var entry : stream) {
                    ObjectId id;
                    try { id = ObjectId.fromFilename(entry.getFileName().toString()); }
                    catch (IllegalArgumentException e) { continue; }
                    String name = id.filename();
                    component(name);
                    beforeInspect.run();
                    try (var pin = libc.openAt(bound, name, LinuxAbi.PIN)) {
                        if (libc.stat(pin).regular()) {
                            candidates.add(new Candidate(id, () -> readCandidate(bound, name)));
                        }
                    }
                }
            } catch (IOException | SecurityException | DirectoryIteratorException e) {
                issue = SnapshotIssue.ENUMERATION_UNAVAILABLE;
            }
            var result = new Snapshot(candidates, issue, family);
            family = null; // snapshot takes ownership
            return result;
        } catch (LinuxBoundFiles.UnsafeRoot e) {
            return empty(SnapshotIssue.UNSAFE_NAMESPACE);
        } catch (LinuxLibc.NativeFailure e) {
            return empty(e.errno == LinuxAbi.ENOTDIR || e.errno == LinuxAbi.ELOOP
                    ? SnapshotIssue.UNSAFE_NAMESPACE : SnapshotIssue.ENUMERATION_UNAVAILABLE);
        } catch (IOException | SecurityException e) {
            return empty(SnapshotIssue.ENUMERATION_UNAVAILABLE);
        } finally {
            if (family != null) { family.close(); }
        }
    }
    private static Snapshot empty(SnapshotIssue issue) { return new Snapshot(List.of(), issue); }
    static void component(String name) {
        if (name.indexOf('/') >= 0 || name.indexOf('\0') >= 0 || name.equals(".") || name.equals("..")) {
            throw new IllegalArgumentException("INVALID_COMPONENT");
        }
    }
    private LinuxFd reopen(LinuxFd pin, LinuxStatx identity) throws IOException {
        return LinuxBoundFiles.reopen(libc, pin, identity, readableIdentity);
    }
    private ReadableByteChannel readCandidate(LinuxFd family, String name) throws IOException {
        component(name);
        LinuxFd readable = null;
        try {
            try (var pin = libc.openAt(family, name, LinuxAbi.PIN)) {
                var identity = libc.stat(pin);
                if (!identity.regular()) { throw new IOException("NOT_REGULAR"); }
                afterPin.run();
                readable = reopen(pin, identity);
            }
            var channel = new LinuxReadChannel(libc, readable);
            readable = null;
            return channel;
        } finally {
            if (readable != null) { readable.close(); }
        }
    }
}
