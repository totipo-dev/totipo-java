package dev.totipo.storage.nio;

import dev.totipo.spi.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;

/** Experimental layout-only NIO provider. Opening observes an existing root without mutation.
 * Same-privilege local filesystem/process namespace is trusted, as in the existing NIO provider.
 * No protocol types, fixed record sizes, authentication or stale policy belong here. */
public final class NioTotipoStore implements TotipoStore {
    private final Path root;
    private final NioObjectStorage objects;
    private final NioVaultStorage vaults;
    private final ScanOperations scans;
    private boolean closed;

    public static NioTotipoStore open(Path root) throws IOException { return open(root, new NioDurability()); }
    public static NioTotipoStore open(Path root, StorageDurability durability) throws IOException {
        return open(root, new NioObjectStorage.Operations(durability),
                new NioVaultStorage.Operations(durability), new ScanOperations());
    }
    static NioTotipoStore open(Path root, NioObjectStorage.Operations objects,
                              NioVaultStorage.Operations vaults, ScanOperations scans) throws IOException {
        return new NioTotipoStore(NioFiles.root(root.toAbsolutePath()), objects, vaults, scans);
    }
    private NioTotipoStore(Path root, NioObjectStorage.Operations objects,
                           NioVaultStorage.Operations vaults, ScanOperations scans) throws IOException {
        this.root = root; this.objects = NioObjectStorage.open(root, objects);
        this.vaults = NioVaultStorage.open(root, vaults); this.scans = scans;
    }
    static class ScanOperations extends NioObjectScan.Operations {}
    private void active() { if (closed) throw new IllegalStateException("Store closed"); }
    @Override public BoundedRead readVault(int expectedBytes) {
        active(); return NioReads.child(root, "vault", expectedBytes);
    }
    @Override public ObjectScan scanObjects() { active(); return NioObjectScan.scan(root, scans); }
    @Override public BoundedRead readObject(ObjectName name, int expectedBytes) {
        active(); Objects.requireNonNull(name); NioReads.expected(expectedBytes);
        if (!NioReads.directName(root, name.value())) return new BoundedRead.Unavailable(StoreFailure.UNSAFE_NAMESPACE);
        try {
            Path directory = NioObjectScan.namespace(root);
            return directory == null ? new BoundedRead.Absent() : NioReads.child(directory, name.value(), expectedBytes);
        } catch (IOException | SecurityException | UnsupportedOperationException failure) {
            return new BoundedRead.Unavailable(NioObjectScan.reason(failure));
        }
    }
    @Override public ObjectWrite publishObject(ObjectName name, byte[] bytes) {
        active(); Objects.requireNonNull(name); Objects.requireNonNull(bytes);
        objects.mutationEntered = false;
        if (!NioReads.directName(root, name.value())) return new ObjectWrite.Failed(StoreFailure.UNSAFE_NAMESPACE);
        try {
            NioFiles.directory(root);
            return objects.publish(name.value(), bytes, true) ? new ObjectWrite.Written() : new ObjectWrite.AlreadyPresentExact();
        } catch (NioObjectStorage.Different different) {
            return new ObjectWrite.ExistingDifferent();
        } catch (IOException | SecurityException | UnsupportedOperationException failure) {
            return objects.mutationEntered ? new ObjectWrite.Uncertain(NioObjectScan.reason(failure)) : new ObjectWrite.Failed(NioObjectScan.reason(failure));
        }
    }
    @Override public VaultPrepare prepareVault(byte[] bytes) {
        active(); Objects.requireNonNull(bytes);
        try { NioFiles.directory(root); return new VaultPrepare.Prepared(new Prepared(vaults.stage(bytes, null))); }
        catch (IOException | SecurityException | UnsupportedOperationException failure) {
            return new VaultPrepare.Failed(NioObjectScan.reason(failure));
        }
    }
    private final class Prepared implements PreparedVault {
        private final NioVaultStorage.Stage stage;
        private boolean consumed;
        Prepared(NioVaultStorage.Stage stage) { this.stage = stage; }
        private void usable() {
            active();
            if (consumed) throw new IllegalStateException("Prepared vault consumed");
            stage.requireActive();
        }
        @Override public BoundedRead readBack(int expectedBytes) { usable(); return stage.readBack(expectedBytes); }
        @Override public VaultInstall installCanonicalIfAbsent() {
            usable(); consumed = true;
            try {
                NioFiles.directory(root);
                if (NioFiles.findExactDirectChild(root, "vault").isPresent()) return new VaultInstall.AlreadyPresent();
                stage.installInitialDurably();
                return new VaultInstall.Installed();
            } catch (FileAlreadyExistsException exists) {
                try {
                    if (NioFiles.findExactDirectChild(root, "vault").isPresent()) return new VaultInstall.AlreadyPresent();
                } catch (IOException | SecurityException ignored) { /* Known no-install collision, unsafe winner. */ }
                return new VaultInstall.Failed(StoreFailure.UNSAFE_NAMESPACE);
            } catch (IOException | SecurityException | UnsupportedOperationException failure) {
                return stage.mutationEntered ? new VaultInstall.Uncertain(NioObjectScan.reason(failure)) : new VaultInstall.Failed(NioObjectScan.reason(failure));
            }
        }
        @Override public VaultReplace replaceCanonical() {
            usable(); consumed = true;
            try {
                NioFiles.directory(root); stage.replaceCanonicalDurably(); return new VaultReplace.Replaced();
            } catch (IOException | SecurityException | UnsupportedOperationException failure) {
                return stage.mutationEntered ? new VaultReplace.Uncertain(NioObjectScan.reason(failure)) : new VaultReplace.Failed(NioObjectScan.reason(failure));
            }
        }
        @Override public void close() { consumed = true; stage.close(); }
    }
    @Override public void close() {
        if (closed) return;
        closed = true; vaults.close(); objects.close();
    }
}
