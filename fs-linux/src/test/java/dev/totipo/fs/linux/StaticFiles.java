package dev.totipo.fs.linux;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;
final class StaticFiles {
    static void fifo(Path path) throws Exception {
        var process = new ProcessBuilder("mkfifo", path.toString()).start();
        try { assertTrue(process.waitFor(5, TimeUnit.SECONDS)); assertEquals(0, process.exitValue()); }
        finally { process.destroyForcibly(); }
    }
}
