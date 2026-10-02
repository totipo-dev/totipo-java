import org.totipo.OpenResult;
import org.totipo.VaultSession;
import org.totipo.VaultState;
import org.totipo.storage.nio.NioTotipo;
import java.nio.file.Path;
import java.util.concurrent.Flow;

/** Compile-only client: no vault, SPI, or implementation internals. */
public final class ConsumerSmoke {
    public static OpenResult open(Path path, char[] password) {
        return NioTotipo.open(path, password);
    }
    public static VaultState state(VaultSession session) {
        return session.state();
    }
    public static Flow.Publisher<VaultState> states(VaultSession session) {
        return session.states();
    }
}
