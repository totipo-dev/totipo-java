package dev.totipo.fs.linux;

import dev.totipo.format.DeviceProvenanceKey;
import dev.totipo.format.DeviceProvenanceKeyStore;
import dev.totipo.format.DeviceProvenancePublicKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable file-backed P-256 custody on Linux amd64/JDK 25 with native access.
 * Caller supplies an existing absolute app-local per-vault directory OUTSIDE
 * synchronized storage, with trusted configured ancestors. No directory is created.
 * Requires procfs, O_TMPFILE, hard links and working file/directory fsync semantics.
 * Private material is exportable PKCS#8 in an owner-only file, not hardware-backed.
 * Local-user compromise can forge attribution; this key alone grants no vault-root
 * authority. Handles are independent of the store and do not watch file replacement.
 * Thread-confined store; the application must keep its established vault configuration
 * stable during identity use. Publication errors are never retried or rolled back.
 */
public final class LinuxDeviceProvenanceKeyStore implements DeviceProvenanceKeyStore {
    static final String NAME = "device-provenance-v1.bin";
    private static final byte[] HEADER = {84, 79, 84, 73, 80, 79, 45, 68, 75, 0, 0, 1};
    private static final byte[] CHECK = "totipo-java/linux-device-key-staging/v1".getBytes(StandardCharsets.US_ASCII);
    private static final int PREFIX = 111, MAX_PRIVATE = 1024, READ_LIMIT = 1136;
    private final LinuxLibc libc;
    private final LinuxFd root;
    private final Operations operations;

    /**
     * Binds an explicit pre-existing app-local directory, rejecting a final symlink.
     * @param localVaultDirectory absolute default-filesystem local secret-storage directory
     * @return caller-owned store
     * @throws IOException if Linux capabilities, root identity or access checks fail
     */
    public static LinuxDeviceProvenanceKeyStore open(Path localVaultDirectory) throws IOException {
        return open(localVaultDirectory, new Operations());
    }
    static LinuxDeviceProvenanceKeyStore open(Path path, Operations operations) throws IOException {
        LinuxBoundFiles.path(path);
        var capability = new LinuxSecureDiscoverySource(path).capability();
        if (capability != LinuxSecureDiscoverySource.Capability.SUPPORTED)
            throw new IOException("DEVICE_KEY_STORAGE_CAPABILITY_" + capability);
        var libc = new LinuxLibc();
        return new LinuxDeviceProvenanceKeyStore(libc,
                LinuxBoundFiles.bindRoot(libc, path, LinuxAbi.DIRECTORY), operations);
    }
    private LinuxDeviceProvenanceKeyStore(LinuxLibc libc, LinuxFd root, Operations operations) {
        this.libc = libc; this.root = root; this.operations = operations;
    }
    /** Small fault/boundary seam; production always performs the actual fd operations. */
    static class Operations {
        void boundary(String name) throws IOException {}
        void pinned() throws IOException {}
        KeyPair generate() throws GeneralSecurityException {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return generator.generateKeyPair();
        }
        int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException { return libc.write(fd, bytes); }
    }
    @Override public DeviceProvenanceKey openExisting() throws IOException, GeneralSecurityException {
        root.number();
        LinuxFd pin;
        try { pin = libc.openAt(root, NAME, LinuxAbi.PIN); }
        catch (LinuxLibc.NativeFailure e) {
            if (e.errno == LinuxAbi.ENOENT) return null;
            throw e;
        }
        // Close the returned key if even the pin close fails.
        DeviceProvenanceKey key = null;
        try {
            try (pin) { operations.pinned(); key = read(pin); }
            var result = key; key = null; return result;
        } finally { if (key != null) key.close(); }
    }
    private static void secure(LinuxStatx identity) throws GeneralSecurityException {
        if (!identity.regular() || (identity.mode() & 0077) != 0)
            throw new GeneralSecurityException("INSECURE_DEVICE_KEY_FILE");
    }
    private DeviceProvenanceKey read(LinuxFd pin) throws IOException, GeneralSecurityException {
        var identity = libc.stat(pin); secure(identity);
        byte[] record = new byte[READ_LIMIT];
        try {
            int length;
            try (var fd = LinuxBoundFiles.reopen(libc, pin, identity, value -> value)) {
                secure(libc.stat(fd));
                var bytes = ByteBuffer.wrap(record);
                while (bytes.hasRemaining()) {
                    int count = libc.read(fd, bytes);
                    if (count < 0) break;
                    if (count == 0) throw new IOException("KEY_READ_NO_PROGRESS");
                }
                length = bytes.position();
            }
            return parse(record, length);
        } finally { Arrays.fill(record, (byte) 0); }
    }
    private static DeviceProvenanceKey parse(byte[] record, int length) throws GeneralSecurityException {
        if (length < PREFIX + 1 || length >= READ_LIMIT) throw invalid();
        for (int i = 0; i < HEADER.length; i++) if (record[i] != HEADER[i]) throw invalid();
        int privateLength = (record[109] & 255) << 8 | (record[110] & 255);
        if (privateLength < 1 || privateLength > MAX_PRIVATE || length != PREFIX + privateLength) throw invalid();
        byte[] encoded = Arrays.copyOfRange(record, PREFIX, length);
        PrivateKey key = null;
        try {
            // KeySpec/provider may retain internal copies; explicit array wiping is best effort only.
            key = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));
            if (!(key instanceof ECPrivateKey ec)) throw invalid();
            var parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            var expected = parameters.getParameterSpec(ECParameterSpec.class);
            var actual = ec.getParams();
            if (actual == null || !expected.getCurve().equals(actual.getCurve())
                    || !expected.getGenerator().equals(actual.getGenerator())
                    || !expected.getOrder().equals(actual.getOrder())
                    || expected.getCofactor() != actual.getCofactor()) throw invalid();
            var result = new LinuxDeviceProvenanceKey(Arrays.copyOfRange(record, 12, 44),
                    Arrays.copyOfRange(record, 44, 109), key);
            key = null; return result;
        } finally { Arrays.fill(encoded, (byte) 0); LinuxDeviceProvenanceKey.destroy(key); }
    }
    private static GeneralSecurityException invalid() { return new GeneralSecurityException("INVALID_DEVICE_KEY_RECORD"); }

    @Override public DeviceProvenanceKey createDurably(byte[] vaultBinding) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(vaultBinding);
        if (vaultBinding.length != 32) throw new IllegalArgumentException("BINDING_LENGTH");
        root.number();
        byte[] binding = vaultBinding.clone(), encoded = null, record = null;
        PrivateKey generated = null;
        try {
            var pair = operations.generate(); generated = pair.getPrivate();
            if (!(pair.getPublic() instanceof ECPublicKey publicKey)) throw invalid();
            byte[] publicBytes;
            try { publicBytes = DeviceProvenancePublicKey.encodeX963(publicKey); }
            catch (IllegalArgumentException e) { throw new GeneralSecurityException("INVALID_GENERATED_PUBLIC_KEY", e); }
            encoded = generated.getEncoded();
            if (!"PKCS#8".equals(generated.getFormat()) || encoded == null
                    || encoded.length < 1 || encoded.length > MAX_PRIVATE)
                throw new GeneralSecurityException("UNSUPPORTED_PRIVATE_KEY_ENCODING");
            record = new byte[PREFIX + encoded.length];
            ByteBuffer.wrap(record).put(HEADER).put(binding).put(publicBytes).putShort((short) encoded.length).put(encoded);
            Arrays.fill(encoded, (byte) 0);
            operations.boundary("temporary");
            try (var stage = libc.temporary(root)) {
                secure(libc.stat(stage));
                var bytes = ByteBuffer.wrap(record).asReadOnlyBuffer();
                while (bytes.hasRemaining()) {
                    int before = bytes.remaining();
                    int written = operations.write(libc, stage, bytes);
                    if (written <= 0 || before - bytes.remaining() != written) throw new IOException("STAGE_WRITE_NO_PROGRESS");
                }
                operations.boundary("initial-sync"); libc.fsync(stage);
                operations.boundary("staged-read");
                try (var staged = read(stage)) {
                    operations.boundary("validation");
                    if (!Arrays.equals(binding, staged.vaultBinding()) || !Arrays.equals(publicBytes, staged.publicKeyX963()))
                        throw invalid();
                    var verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(publicKey); verifier.update(CHECK);
                    if (!verifier.verify(staged.signSha256Ecdsa(CHECK))) throw invalid();
                }
                operations.boundary("link"); libc.link(stage, root, NAME);
                operations.boundary("post-link-sync"); libc.fsync(stage);
                operations.boundary("directory-sync"); libc.fsync(root);
            }
            LinuxDeviceProvenanceKey.destroy(generated); generated = null;
            Arrays.fill(record, (byte) 0);
            operations.boundary("persisted-reopen");
            var persisted = openExisting();
            if (persisted == null) throw new IOException("PERSISTED_KEY_ABSENT");
            // A namespace replacement must not turn successful creation into another identity.
            if (!Arrays.equals(binding, persisted.vaultBinding()) || !Arrays.equals(publicBytes, persisted.publicKeyX963())) {
                persisted.close(); throw new IOException("PERSISTED_KEY_CHANGED");
            }
            return persisted;
        } finally {
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
            if (record != null) Arrays.fill(record, (byte) 0);
            LinuxDeviceProvenanceKey.destroy(generated);
        }
    }
    @Override public void close() throws IOException { root.close(); }
}
