package dev.totipo.spi;

/** Experimental provider SPI. Understands root/vault/objects-v1 and opaque storage only.
 * Construction is read-only. Calls are synchronous; inputs remain caller-owned.
 * Writes neither mutate nor retain caller arrays without copying.
 * Passing this store to Totipo.open/create transfers ownership on every outcome.
 * Calls are serialized by core; providers need not support concurrent use of one handle.
 * Close is idempotent and never removes canonical state. */
public interface TotipoStore extends AutoCloseable {
    BoundedRead readVault(int expectedBytes);
    ObjectScan scanObjects();
    BoundedRead readObject(ObjectName name, int expectedBytes);
    ObjectWrite publishObject(ObjectName name, byte[] bytes);
    VaultPrepare prepareVault(byte[] bytes);
    @Override void close();
}
