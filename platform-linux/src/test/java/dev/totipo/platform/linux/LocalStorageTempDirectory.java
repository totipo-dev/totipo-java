package dev.totipo.platform.linux;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.extension.AnnotatedElementContext;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.io.TempDirFactory;

/** Test fixtures on the configured local checkout filesystem; JUnit owns their cleanup. */
public final class LocalStorageTempDirectory implements TempDirFactory {
    @Override public Path createTempDirectory(AnnotatedElementContext element, ExtensionContext context) throws IOException {
        Path parent=Path.of(System.getProperty("totipo.test.local-storage-directory"));
        Files.createDirectories(parent);
        return Files.createTempDirectory(parent,"journal-");
    }
}
