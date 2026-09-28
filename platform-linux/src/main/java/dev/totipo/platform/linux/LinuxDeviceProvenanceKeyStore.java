package dev.totipo.platform.linux;

import dev.totipo.format.DeviceProvenanceKey;
import dev.totipo.format.DeviceProvenanceKeyStore;
import dev.totipo.format.DeviceProvenancePublicKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.channels.FileChannel;
import java.nio.file.attribute.PosixFileAttributes;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.Objects;

/** Immutable owner-only P-256 custody in a pre-existing app-local directory outside
 * synchronized storage. NIO staging, no-replace hard links and directory fsync preserve
 * crash durability. PKCS#8 material is exportable; this is not hardware-backed custody. */
public final class LinuxDeviceProvenanceKeyStore implements DeviceProvenanceKeyStore {
    static final String NAME = "device-provenance-v1.bin";
    private static final byte[] HEADER = {84, 79, 84, 73, 80, 79, 45, 68, 75, 0, 0, 1};
    private static final byte[] CHECK = "totipo-java/linux-device-key-staging/v1".getBytes(StandardCharsets.US_ASCII);
    private static final int PREFIX = 111, MAX_PRIVATE = 1024, READ_LIMIT = 1136;
    private final Path root;
    private boolean closed;
    private final Operations operations;

    public static LinuxDeviceProvenanceKeyStore open(Path path) throws IOException {
        return open(path, new Operations());
    }
    static LinuxDeviceProvenanceKeyStore open(Path path, Operations operations) throws IOException {
        return new LinuxDeviceProvenanceKeyStore(LocalPrivateFiles.root(path), operations);
    }
    private LinuxDeviceProvenanceKeyStore(Path root, Operations operations) {
        this.root = root; this.operations = operations;
    }
    static class Operations {
        void boundary(String name) throws IOException {}
        KeyPair generate() throws GeneralSecurityException {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return generator.generateKeyPair();
        }
        int write(FileChannel channel, ByteBuffer bytes) throws IOException { return channel.write(bytes); }
    }
    private void usable() throws IOException { if (closed) throw new IOException("STORE_CLOSED"); }
    @Override public DeviceProvenanceKey openExisting() throws IOException, GeneralSecurityException {
        usable();
        Path file = root.resolve(NAME);
        try { Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS); }
        catch (NoSuchFileException absent) { return null; }
        return read(file);
    }
    private DeviceProvenanceKey read(Path file) throws IOException, GeneralSecurityException {
        var attrs = Files.readAttributes(file, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attrs.isRegularFile() || attrs.permissions().stream().anyMatch(p -> !p.name().startsWith("OWNER_")))
            throw new GeneralSecurityException("INSECURE_DEVICE_KEY_FILE");
        byte[] record = LocalPrivateFiles.read(file, READ_LIMIT);
        try { return parse(record, record.length); }
        finally { Arrays.fill(record, (byte) 0); }
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
        usable(); LinuxDurability.requireAvailable();
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
            Path temp = LocalPrivateFiles.temporary(root, ".totipo-device-key-");
            try (var stage = FileChannel.open(temp, StandardOpenOption.WRITE)) {
                var bytes = ByteBuffer.wrap(record).asReadOnlyBuffer();
                while (bytes.hasRemaining()) {
                    int before = bytes.remaining();
                    int written = operations.write(stage, bytes);
                    if (written <= 0 || before - bytes.remaining() != written) throw new IOException("STAGE_WRITE_NO_PROGRESS");
                }
                operations.boundary("initial-sync"); stage.force(true);
                operations.boundary("staged-read");
                try (var staged = read(temp)) {
                    operations.boundary("validation");
                    if (!Arrays.equals(binding, staged.vaultBinding()) || !Arrays.equals(publicBytes, staged.publicKeyX963()))
                        throw invalid();
                    var verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(publicKey); verifier.update(CHECK);
                    if (!verifier.verify(staged.signSha256Ecdsa(CHECK))) throw invalid();
                }
                operations.boundary("link"); Files.createLink(root.resolve(NAME), temp);
                operations.boundary("post-link-sync"); stage.force(true);
                operations.boundary("directory-sync"); LinuxDurability.open().syncDirectory(root);
            } finally { LocalPrivateFiles.cleanup(temp); }
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
    @Override public void close() { closed = true; }
}
