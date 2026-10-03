package org.totipo.storage.nio;

import org.totipo.CreateVaultResult;
import org.totipo.OpenResult;
import org.totipo.Totipo;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Objects;

/** Application entry point. Both methods may block for KDF and configured-store I/O.
 * The path must identify an existing configured-store directory.
 * This library entry point does not claim v1 application conformance. Interactive callers
 * must confirm empty-password creation. Creation reports no pre-install orphan context;
 * provider integrations can use the SPI for available observation before creation.
 * Orphan-looking names do not veto creation or require exhaustive enumeration. */
public final class NioTotipo {
    private NioTotipo() { }
    public static OpenResult open(Path path, char[] password) {
        Objects.requireNonNull(path); Objects.requireNonNull(password);
        Path root = path.toAbsolutePath();
        try {
            return Totipo.open(NioTotipoStore.open(root), password);
        } catch (IOException | SecurityException | UnsupportedOperationException unavailable) {
            return new OpenResult.Unavailable();
        }
    }
    public static CreateVaultResult create(Path path, char[] password) {
        Objects.requireNonNull(path); Objects.requireNonNull(password);
        Path root = path.toAbsolutePath();
        try {
            return Totipo.create(NioTotipoStore.open(root), password);
        } catch (IOException | SecurityException | UnsupportedOperationException unavailable) {
            return new CreateVaultResult.Failed();
        }
    }
}
