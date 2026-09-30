package dev.totipo.storage.nio;

import dev.totipo.CreateVaultResult;
import dev.totipo.OpenResult;
import dev.totipo.format.ApplicationVaults;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

/** Application entry point. Both methods may block for KDF and configured-store I/O.
 * The path must identify an existing configured-store directory. */
public final class NioTotipo {
    private NioTotipo() { }
    public static OpenResult open(Path path, char[] password) {
        Objects.requireNonNull(path); Objects.requireNonNull(password);
        Path root = path.toAbsolutePath();
        var durability = new NioDurability();
        NioVaultBootstrapStorage bootstrap = null;
        try {
            bootstrap = NioVaultBootstrapStorage.open(root, durability);
            var publication = new NioApplicationPublication(root, durability);
            return ApplicationVaults.open(bootstrap, new NioDiscoverySource(root), publication, password);
        } catch (IOException | SecurityException | UnsupportedOperationException unavailable) {
            if (bootstrap != null) bootstrap.close();
            return new OpenResult.Unavailable();
        }
    }
    public static CreateVaultResult create(Path path, char[] password) {
        Objects.requireNonNull(path); Objects.requireNonNull(password);
        Path root = path.toAbsolutePath();
        var durability = new NioDurability();
        NioVaultBootstrapStorage bootstrap = null;
        try {
            bootstrap = NioVaultBootstrapStorage.open(root, durability);
            var publication = new NioApplicationPublication(root, durability);
            return ApplicationVaults.create(bootstrap, new NioDiscoverySource(root), publication, password);
        } catch (IOException | SecurityException | UnsupportedOperationException unavailable) {
            if (bootstrap != null) bootstrap.close();
            return new CreateVaultResult.Failed();
        }
    }
}
