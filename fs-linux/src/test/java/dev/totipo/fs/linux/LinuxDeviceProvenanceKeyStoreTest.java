package dev.totipo.fs.linux;

import dev.totipo.format.*;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.*;
import java.nio.channels.ServerSocketChannel;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(45)
class LinuxDeviceProvenanceKeyStoreTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path root;
    static final String NAME = "device-provenance-v1.bin";
    Path file() { return root.resolve(NAME); }
    static KeyPair pair(String curve) throws Exception {
        var g = KeyPairGenerator.getInstance("EC"); g.initialize(new ECGenParameterSpec(curve)); return g.generateKeyPair();
    }
    static void verify(DeviceProvenanceKey key) throws Exception {
        byte[] b = key.publicKeyX963();
        var p = AlgorithmParameters.getInstance("EC"); p.init(new ECGenParameterSpec("secp256r1"));
        var pub = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(
                new BigInteger(1, Arrays.copyOfRange(b, 1, 33)), new BigInteger(1, Arrays.copyOfRange(b, 33, 65))),
                p.getParameterSpec(ECParameterSpec.class)));
        byte[] message = {3, 1, 4, 1, 5}, before = message.clone();
        byte[] signature = key.signSha256Ecdsa(message);
        assertTrue(signature.length > 0 && signature.length <= 72);
        var v = Signature.getInstance("SHA256withECDSA"); v.initVerify(pub); v.update(message);
        assertTrue(v.verify(signature)); assertArrayEquals(before, message);
    }
    byte[] create() throws Exception {
        try (var store = LinuxDeviceProvenanceKeyStore.open(root); var key = store.createDurably(new byte[32])) { verify(key); }
        return Files.readAllBytes(file());
    }
    void write(byte[] bytes) throws Exception {
        Files.write(file(), bytes); Files.setAttribute(file(), "unix:mode", 0600);
    }
    @Test void exactFormatIndependentKeysAndDefensiveHandleLifetime() throws Exception {
        var faults = new DeviceKeyFaults(); faults.writeLimit = 7;
        byte[] binding = new byte[32]; Arrays.fill(binding, (byte) 37);
        byte[] original = binding.clone();
        faults.action = name -> { if (name.equals("temporary")) Arrays.fill(binding, (byte) 9); };
        var store = faults.open(root);
        assertNull(store.openExisting());
        var key = store.createDurably(binding);
        byte[] bytes = Files.readAllBytes(file()), publicKey = key.publicKeyX963();
        assertEquals("544f5449504f2d444b000001", HexFormat.of().formatHex(bytes, 0, 12));
        assertArrayEquals(original, Arrays.copyOfRange(bytes, 12, 44));
        assertArrayEquals(publicKey, Arrays.copyOfRange(bytes, 44, 109));
        int n = Short.toUnsignedInt(ByteBuffer.wrap(bytes).getShort(109));
        assertEquals(111 + n, bytes.length); assertTrue(n >= 1 && n <= 1024);
        assertEquals(0, (int) Files.getAttribute(file(), "unix:mode") & 0077);
        assertEquals(List.of("temporary", "initial-sync", "staged-read", "validation", "link", "post-link-sync", "directory-sync", "persisted-reopen"),
                faults.events.stream().filter(e -> !e.equals("write")).toList());
        byte[] wiped = new byte[faults.observed.capacity()]; faults.observed.get(wiped);
        assertArrayEquals(new byte[wiped.length], wiped);
        store.close(); store.close(); verify(key);
        assertThrows(IOException.class, store::openExisting);
        assertThrows(IOException.class, () -> store.createDurably(original));
        byte[] copy = key.vaultBinding(); copy[0] ^= 1; assertArrayEquals(original, key.vaultBinding());
        copy = key.publicKeyX963(); copy[0] ^= 1; assertArrayEquals(publicKey, key.publicKeyX963());
        assertThrows(NullPointerException.class, () -> key.signSha256Ecdsa(null));
        key.close(); key.close(); assertThrows(IllegalStateException.class, () -> key.signSha256Ecdsa(new byte[0]));
        assertThrows(IllegalStateException.class, key::vaultBinding); assertThrows(IllegalStateException.class, key::publicKeyX963);
        try (var next = LinuxDeviceProvenanceKeyStore.open(root); var loaded = next.openExisting()) {
            assertArrayEquals(publicKey, loaded.publicKeyX963()); assertArrayEquals(original, loaded.vaultBinding()); verify(loaded);
        }
        assertArrayEquals(bytes, Files.readAllBytes(file()));
        try (var other = LinuxDeviceProvenanceKeyStore.open(Files.createDirectory(root.resolve("other")));
             var independent = other.createDurably(original)) { assertFalse(Arrays.equals(publicKey, independent.publicKeyX963())); }
    }
    @Test void rootContractAndBoundDirectorySurviveRename() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> LinuxDeviceProvenanceKeyStore.open(Path.of("relative")));
        assertThrows(IOException.class, () -> LinuxDeviceProvenanceKeyStore.open(root.resolve("missing")));
        assertFalse(Files.exists(root.resolve("missing")));
        assertThrows(IOException.class, () -> LinuxDeviceProvenanceKeyStore.open(Files.write(root.resolve("regular"), new byte[0])));
        assertThrows(IOException.class, () -> LinuxDeviceProvenanceKeyStore.open(Files.createSymbolicLink(root.resolve("link"), root)));
        try (var zip = FileSystems.newFileSystem(URI.create("jar:" + root.resolve("zip").toUri()), Map.of("create", "true"))) {
            assertThrows(IllegalArgumentException.class, () -> LinuxDeviceProvenanceKeyStore.open(zip.getPath("/")));
        }
        Path configured = Files.createDirectory(root.resolve("configured")), moved = root.resolve("moved");
        try (var store = LinuxDeviceProvenanceKeyStore.open(configured)) {
            assertThrows(NullPointerException.class, () -> store.createDurably(null));
            assertThrows(IllegalArgumentException.class, () -> store.createDurably(new byte[31]));
            Files.move(configured, moved); Files.createDirectory(configured);
            try (var key = store.createDurably(new byte[32])) { verify(key); }
            assertTrue(Files.exists(moved.resolve(NAME))); assertFalse(Files.exists(configured.resolve(NAME)));
        }
    }
    @Test void onlyExactFilenameCounts() throws Exception {
        for (String suffix : List.of(".tmp", ".backup", ".conflict")) Files.write(root.resolve(NAME + suffix), new byte[]{1});
        try (var store = LinuxDeviceProvenanceKeyStore.open(root)) { assertNull(store.openExisting()); }
    }
    @Test void permissionsFailClosedWithoutRepair() throws Exception {
        create();
        try (var store = LinuxDeviceProvenanceKeyStore.open(root)) {
            for (int mode : new int[]{0644, 0640, 0604}) {
                Files.setAttribute(file(), "unix:mode", mode);
                assertThrows(GeneralSecurityException.class, store::openExisting);
                assertEquals(mode, (int) Files.getAttribute(file(), "unix:mode") & 0777);
            }
            for (int mode : new int[]{0600, 0400}) {
                Files.setAttribute(file(), "unix:mode", mode);
                try (var key = store.openExisting()) { verify(key); }
            }
        }
    }
    @Test void specialFilesNeverBlockFollowOrReplace() throws Exception {
        Path shortRoot = Files.createTempDirectory("dk-");
        Path path = shortRoot.resolve(NAME);
        try (var store = LinuxDeviceProvenanceKeyStore.open(shortRoot)) {
            for (String form : List.of("symlink", "directory", "fifo", "socket")) {
                try (var socket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
                    switch (form) {
                        case "symlink" -> Files.createSymbolicLink(path, Path.of("/dev/zero"));
                        case "directory" -> Files.createDirectory(path);
                        case "fifo" -> LinuxSecureSourceTest.fifo(path);
                        case "socket" -> socket.bind(UnixDomainSocketAddress.of(path));
                        default -> throw new AssertionError();
                    }
                    assertThrows(GeneralSecurityException.class, store::openExisting);
                    assertEquals(LinuxAbi.EEXIST, assertThrows(LinuxLibc.NativeFailure.class,
                            () -> store.createDurably(new byte[32])).errno);
                    assertTrue(Files.exists(path, LinkOption.NOFOLLOW_LINKS)); Files.delete(path);
                }
            }
        } finally { Files.deleteIfExists(path); Files.delete(shortRoot); }
    }
    @Test void hostileRecordMatrixAndHugeSparseFile() throws Exception {
        byte[] good = create();
        var bad = new ArrayList<byte[]>();
        for (int n : new int[]{0, 1, 9, 10, 11, 12, 43, 44, 108, 109, 110, 111, good.length - 1}) bad.add(Arrays.copyOf(good, n));
        for (int index : new int[]{0, 9, 10, 11}) { byte[] b = good.clone(); b[index] ^= 1; bad.add(b); }
        byte[] v2 = good.clone(); v2[11] = 2; bad.add(v2);
        byte[] swapped = good.clone(); swapped[10] = 1; swapped[11] = 0; bad.add(swapped);
        for (int n : new int[]{0, 1025, 65535, good.length - 112, good.length - 110}) {
            byte[] b = good.clone(); ByteBuffer.wrap(b).putShort(109, (short) n); bad.add(b);
        }
        bad.add(Arrays.copyOf(good, good.length + 1));
        byte[] paddedDer = Arrays.copyOf(good, good.length + 1);
        ByteBuffer.wrap(paddedDer).putShort(109, (short) (paddedDer.length - 111)); bad.add(paddedDer);
        byte[] der = good.clone(); der[111] = 0; bad.add(der);
        byte[] other = pair("secp384r1").getPrivate().getEncoded();
        byte[] wrongCurve = Arrays.copyOf(good, 111 + other.length);
        ByteBuffer.wrap(wrongCurve).putShort(109, (short) other.length); System.arraycopy(other, 0, wrongCurve, 111, other.length); bad.add(wrongCurve);
        try (var store = LinuxDeviceProvenanceKeyStore.open(root)) {
            for (byte[] bytes : bad) { write(bytes); assertThrows(GeneralSecurityException.class, store::openExisting); assertArrayEquals(bytes, Files.readAllBytes(file())); }
            try (var f = new RandomAccessFile(file().toFile(), "rw")) { f.setLength(1L << 40); }
            assertThrows(GeneralSecurityException.class, store::openExisting);
            assertEquals(1L << 40, Files.size(file()));
        }
    }
    @Test void pinAndLoadedHandleStayWithOriginalInode() throws Exception {
        byte[] original = create();
        Path replacement = Files.createDirectory(root.resolve("replacement"));
        byte[] nextPublic;
        try (var store = LinuxDeviceProvenanceKeyStore.open(replacement); var key = store.createDurably(new byte[32])) { nextPublic = key.publicKeyX963(); }
        var faults = new DeviceKeyFaults();
        faults.action = name -> {
            if (name.equals("pinned")) {
                Files.move(replacement.resolve(NAME), file(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                faults.action = ignored -> {};
            }
        };
        try (var store = faults.open(root); var old = store.openExisting(); var next = store.openExisting()) {
            assertArrayEquals(Arrays.copyOfRange(original, 44, 109), old.publicKeyX963());
            assertArrayEquals(nextPublic, next.publicKeyX963()); verify(old); verify(next);
            Files.delete(file()); verify(old); verify(next); assertNull(store.openExisting());
        }
    }
    @Test void faultMatrixWipesSerializationAndPreservesAmbiguousPublication() throws Exception {
        for (String failure : List.of("temporary", "write", "partial-write", "zero", "initial-sync", "staged-read", "validation", "link", "post-link-sync", "directory-sync", "persisted-reopen")) {
            Path dir = Files.createDirectory(root.resolve(failure));
            var faults = new DeviceKeyFaults(); faults.fail = failure; faults.writeLimit = 7;
            try (var store = faults.open(dir)) { assertThrows(IOException.class, () -> store.createDurably(new byte[32])); }
            assertEquals(1, faults.generations);
            if (faults.observed != null) { byte[] seen = new byte[faults.observed.capacity()]; faults.observed.get(seen); assertArrayEquals(new byte[seen.length], seen); }
            boolean published = List.of("post-link-sync", "directory-sync", "persisted-reopen").contains(failure);
            try (var paths = Files.list(dir)) { assertEquals(published ? 1 : 0, paths.count()); }
            try (var store = LinuxDeviceProvenanceKeyStore.open(dir); var key = store.openExisting()) {
                if (published) verify(key); else assertNull(key);
            }
        }
    }
    @Test void realStagingMismatchCannotPublish() throws Exception {
        var a = pair("secp256r1"); var b = pair("secp256r1");
        var faults = new DeviceKeyFaults(); faults.pair = new KeyPair(a.getPublic(), b.getPrivate());
        try (var store = faults.open(root)) { assertThrows(GeneralSecurityException.class, () -> store.createDurably(new byte[32])); }
        assertFalse(Files.exists(file())); assertFalse(faults.events.contains("link"));
    }
    @Test void stagedSerializationMustReparseAndMatchOriginalMetadata() throws Exception {
        for (int offset : new int[]{0, 12, 44, 111}) {
            Path dir = Files.createDirectory(root.resolve("corrupt-" + offset));
            var operations = new LinuxDeviceProvenanceKeyStore.Operations() {
                @Override int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException {
                    byte[] bad = new byte[bytes.remaining()]; bytes.duplicate().get(bad); bad[offset] ^= 1;
                    try {
                        var altered = ByteBuffer.wrap(bad);
                        while (altered.hasRemaining()) if (libc.write(fd, altered) <= 0) throw new IOException("no progress");
                        bytes.position(bytes.limit()); return bad.length;
                    } finally { Arrays.fill(bad, (byte) 0); }
                }
            };
            try (var store = LinuxDeviceProvenanceKeyStore.open(dir, operations)) {
                assertThrows(GeneralSecurityException.class, () -> store.createDurably(new byte[32]));
            }
            try (var paths = Files.list(dir)) { assertEquals(0, paths.count()); }
        }
    }
    @Test void generatedExportAndTransientHandleCleanedOnSuccessAndFailure() throws Exception {
        for (String failure : List.of("", "temporary", "write", "validation", "post-link-sync", "persisted-reopen")) {
            Path dir = Files.createDirectory(root.resolve("cleanup-" + failure));
            var pair = pair("secp256r1"); byte[] export = pair.getPrivate().getEncoded(); boolean[] destroyed = {false};
            var wrapper = new PrivateKey() {
                @Override public String getAlgorithm() { return "EC"; }
                @Override public String getFormat() { return "PKCS#8"; }
                @Override public byte[] getEncoded() { return export; }
                @Override public void destroy() { destroyed[0] = true; }
            };
            var faults = new DeviceKeyFaults(); faults.pair = new KeyPair(pair.getPublic(), wrapper); faults.fail = failure;
            try (var store = faults.open(dir)) {
                if (failure.isEmpty()) try (var key = store.createDurably(new byte[32])) { verify(key); }
                else assertThrows(IOException.class, () -> store.createDurably(new byte[32]));
            }
            assertTrue(destroyed[0]); assertArrayEquals(new byte[export.length], export);
        }
    }
    @Test void destroyFailureCannotResurrectClosedSigner() {
        var privateKey = new PrivateKey() {
            @Override public String getAlgorithm() { return "EC"; }
            @Override public String getFormat() { throw new AssertionError(); }
            @Override public byte[] getEncoded() { throw new AssertionError(); }
            @Override public void destroy() throws javax.security.auth.DestroyFailedException { throw new javax.security.auth.DestroyFailedException(); }
        };
        var key = new LinuxDeviceProvenanceKey(new byte[32], new byte[65], privateKey);
        key.close(); key.close(); assertThrows(IllegalStateException.class, () -> key.signSha256Ecdsa(new byte[0]));
    }
    @Test void durablePublicationCannotSubstituteTransientKeyWhenReopenFindsChangedState() throws Exception {
        for (String change : List.of("missing", "corrupt", "other")) {
            Path dir = Files.createDirectory(root.resolve(change));
            Path other = Files.createDirectory(root.resolve(change + "-other"));
            try (var store = LinuxDeviceProvenanceKeyStore.open(other); var key = store.createDurably(new byte[32])) { verify(key); }
            var faults = new DeviceKeyFaults();
            faults.action = name -> {
                if (name.equals("persisted-reopen")) {
                    Files.move(dir.resolve(NAME), dir.resolve("externally-moved"));
                    if (change.equals("corrupt")) { Files.write(dir.resolve(NAME), new byte[]{0}); Files.setAttribute(dir.resolve(NAME), "unix:mode", 0600); }
                    if (change.equals("other")) Files.move(other.resolve(NAME), dir.resolve(NAME));
                }
            };
            try (var store = faults.open(dir)) {
                if (change.equals("corrupt")) assertThrows(GeneralSecurityException.class, () -> store.createDurably(new byte[32]));
                else assertThrows(IOException.class, () -> store.createDurably(new byte[32]));
            }
            assertTrue(Files.exists(dir.resolve("externally-moved"))); assertEquals(1, faults.generations);
        }
    }
    @Test void unsupportedEncodingFailsBeforeStagingAndWipesExport() throws Exception {
        for (String mode : List.of("null", "format", "empty", "oversize")) {
            var p = pair("secp256r1"); byte[] export = mode.equals("null") ? null : new byte[mode.equals("empty") ? 0 : mode.equals("oversize") ? 1025 : 16];
            if (export != null) Arrays.fill(export, (byte) 42);
            boolean[] destroyed = {false};
            var privateKey = new PrivateKey() {
                @Override public String getAlgorithm() { return "EC"; }
                @Override public String getFormat() { return mode.equals("format") ? "RAW" : "PKCS#8"; }
                @Override public byte[] getEncoded() { return export; }
                @Override public void destroy() { destroyed[0] = true; }
            };
            var faults = new DeviceKeyFaults(); faults.pair = new KeyPair(p.getPublic(), privateKey);
            try (var store = faults.open(root)) { assertThrows(GeneralSecurityException.class, () -> store.createDurably(new byte[32])); }
            assertTrue(destroyed[0]); if (export != null) assertArrayEquals(new byte[export.length], export);
            assertTrue(faults.events.isEmpty()); assertFalse(Files.exists(file()));
        }
    }
    @Test void deterministicCreationRaceHasExactlyOneWinnerAndNoAdoption() throws Exception {
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<byte[]>> futures = new ArrayList<>();
            for (int i = 0; i < 2; i++) futures.add(executor.submit(() -> {
                var faults = new DeviceKeyFaults();
                faults.action = name -> { if (name.equals("link")) try { barrier.await(10, TimeUnit.SECONDS); } catch (Exception e) { throw new IOException(e); } };
                try (var store = faults.open(root)) {
                    assertNull(store.openExisting());
                    try (var key = store.createDurably(new byte[32])) { verify(key); return key.publicKeyX963(); }
                    catch (LinuxLibc.NativeFailure e) { assertEquals(LinuxAbi.EEXIST, e.errno); return null; }
                    finally { assertEquals(1, faults.generations); }
                }
            }));
            byte[] a = futures.get(0).get(), b = futures.get(1).get(); assertNotEquals(a == null, b == null);
            try (var store = LinuxDeviceProvenanceKeyStore.open(root); var key = store.openExisting()) {
                assertArrayEquals(a == null ? b : a, key.publicKeyX963()); verify(key);
            }
            try (var paths = Files.list(root)) { assertEquals(List.of(NAME), paths.map(p -> p.getFileName().toString()).toList()); }
        }
    }
}
