import org.totipo.OpenResult;
import org.totipo.VaultSession;
import org.totipo.VaultState;
import org.totipo.storage.nio.NioTotipo;
import java.nio.file.Path;
import java.util.concurrent.Flow;

/** Compile/runtime client: no vault mutation, SPI, or implementation internals. */
public final class ConsumerSmoke {
    public static void main(String[] args) throws ClassNotFoundException {
        // Loading verifies that published runtime classes and runtime-only BC resolve.
        Class.forName(NioTotipo.class.getName());
        Class.forName(VaultSession.class.getName());
        Class.forName(VaultState.class.getName());
        Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator");
        System.out.println("Published API and runtime-only BC load successfully");
    }
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
