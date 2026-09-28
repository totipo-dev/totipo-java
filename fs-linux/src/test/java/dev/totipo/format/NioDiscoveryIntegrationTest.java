package dev.totipo.format;

import dev.totipo.fs.linux.NioDiscoverySource;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static dev.totipo.format.NioTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class NioDiscoveryIntegrationTest {
    @TempDir Path root;
    @Test void validExistingObjectIsLearnedWithoutNativeDurabilityAccess() throws Exception {
        var fixture = fixture(TOKEN);
        Files.write(Files.createDirectory(root.resolve("objects-v1")).resolve(fixture.id().filename()), fixture.bytes());
        var locations = new ArrayList<String>();
        for (Class<?> type : List.of(ReadOnlyProbe.class, NioDiscoverySource.class, DiscoverySource.class,
                Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator")))
            locations.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        var process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--illegal-native-access=deny", "-cp", String.join(java.io.File.pathSeparator, locations),
                ReadOnlyProbe.class.getName(), root.toString(), java.util.HexFormat.of().formatHex(fixture.root()),
                fixture.id().filename()).redirectErrorStream(true).start();
        try {
            assertTrue(process.waitFor(15, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(0, process.exitValue(), new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
        } finally { process.destroyForcibly(); }
        assertArrayEquals(fixture.bytes(), Files.readAllBytes(root.resolve("objects-v1").resolve(fixture.id().filename())));
    }
    public static final class ReadOnlyProbe {
        public static void main(String[] args) {
            int[] commits = {0};
            var result = DiscoveryCoordinator.discover(new NioDiscoverySource(Path.of(args[0])),
                    java.util.HexFormat.of().parseHex(args[1]), DurableKnowledgeState.establishedEmpty(),
                    observation -> { commits[0]++; return DurableKnowledgeState.PersistenceResult.COMMITTED; });
            if (!result.resourceComplete() || commits[0] != 1
                    || result.knowledge().record(ObjectId.fromFilename(args[2])) == null)
                throw new AssertionError("Discovery must authenticate/learn without synchronized-file fsync");
        }
    }
    @Test void nonemptyDiscoveryIsReadyAndComposesWithM23() throws Exception {
        var token = fixture(TOKEN); Path dir = Files.createDirectory(root.resolve("objects-v1"));
        Files.write(dir.resolve(token.id().filename()), token.bytes());
        var result = run(new NioDiscoverySource(root), token.root(), DurableKnowledgeState.establishedEmpty());
        assertTrue(result.resourceComplete()); assertEquals(DiscoveryState.READY, result.discoveryState());
        assertEquals(1, result.knowledge().size());
        assertNotNull(result.topology().record(token.id()));
        assertNotNull(result.readable().get(token.id()));
        assertTrue(policy(result, result.readable().get(token.id()).tokenId()).ordinaryUse().eligible());
    }
    @Test void opaqueClassificationAndPhysicalCreationOrderAreUnchanged() throws Exception {
        var token = fixture(TOKEN); var future = fixture(FUTURE);
        var unscoped = fixture("v1.routing.unknown-type-unscoped.001");
        var objects = List.of(token, future, unscoped);
        DiscoveryResult first = null;
        for (int order = 0; order < 2; order++) {
            Path sync = Files.createDirectory(root.resolve("order" + order));
            Path dir = Files.createDirectory(sync.resolve("objects-v1"));
            for (var object : order == 0 ? objects : objects.reversed()) {
                Files.write(dir.resolve(object.id().filename()), object.bytes());
            }
            var result = run(new NioDiscoverySource(sync), token.root(), DurableKnowledgeState.establishedEmpty());
            assertEquals(DiscoveryState.READY, result.discoveryState()); assertEquals(3, result.knowledge().size());
            assertTrue(result.knowledge().record(unscoped.id()) instanceof OpaqueUnscopedRecord);
            assertEquals(List.of(ObjectDiscovery.Classification.SUPPORTED_VALID,
                    ObjectDiscovery.Classification.OPAQUE_ROUTABLE, ObjectDiscovery.Classification.OPAQUE_UNSCOPED).stream().sorted().toList(),
                    result.observations().stream().map(ObjectDiscovery.Observation::classification).sorted().toList());
            if (first != null) {
                assertEquals(first.knowledge().records(), result.knowledge().records());
                assertEquals(first.observations().stream().map(ObjectDiscovery.Observation::id).toList(),
                        result.observations().stream().map(ObjectDiscovery.Observation::id).toList());
            }
            first = result;
        }
    }
    @Test void wrongSizesAreTerminalAndLargeReadsRemainBounded() throws Exception {
        Path dir = Files.createDirectory(root.resolve("objects-v1"));
        int[] sizes = {0, 1023, 1024, 1025, 200_000};
        for (int i = 0; i < sizes.length; i++) { Files.write(dir.resolve(Integer.toHexString(i).repeat(64)), new byte[sizes[i]]); }
        var source = new NioDiscoverySource(root);
        var readCounts = new ArrayList<AtomicInteger>();
        DiscoverySource counting = () -> {
            var snapshot = source.snapshot(); var candidates = new ArrayList<DiscoverySource.Candidate>();
            for (var candidate : snapshot.candidates()) {
                var count = new AtomicInteger(); readCounts.add(count);
                candidates.add(new DiscoverySource.Candidate(candidate.id(), () -> {
                    var channel = candidate.opener().open();
                    return new ReadableByteChannel() {
                        public int read(ByteBuffer dst) throws IOException {
                            int n = channel.read(dst); if (n > 0) { count.addAndGet(n); } return n;
                        }
                        public boolean isOpen() { return channel.isOpen(); }
                        public void close() throws IOException { channel.close(); }
                    };
                }));
            }
            return new DiscoverySource.Snapshot(candidates, snapshot.issue(), snapshot);
        };
        var result = run(counting, new byte[32], DurableKnowledgeState.establishedEmpty());
        assertEquals(DiscoveryState.READY, result.discoveryState());
        assertTrue(result.observations().stream().allMatch(o -> o.classification() == ObjectDiscovery.Classification.INVALID_STORAGE));
        assertEquals(List.of(0, 1023, 1024, 1025, 1025), readCounts.stream().map(AtomicInteger::get).toList());
    }
    @Test void knownCorruptionRereadsBytesRetainsNodesAndDisappearanceIsIncomplete() throws Exception {
        Path dir = Files.createDirectory(root.resolve("objects-v1")); var token = fixture(TOKEN);
        Path path = dir.resolve(token.id().filename()); Files.write(path, token.bytes());
        var source = new NioDiscoverySource(root);
        var first = run(source, token.root(), DurableKnowledgeState.establishedEmpty());
        var timestamp = Files.getLastModifiedTime(path);
        for (int size : List.of(1024, 1023)) {
            Files.write(path, new byte[size]); Files.setLastModifiedTime(path, timestamp);
            var result = run(source, token.root(), first.knowledge());
            assertEquals(first.knowledge().records(), result.knowledge().records());
            assertTrue(result.readable().evidence().isEmpty()); assertEquals(DiscoveryState.READY, result.discoveryState());
            assertEquals(size == 1024 ? ObjectDiscovery.Detail.AEAD : ObjectDiscovery.Detail.WRONG_LENGTH,
                    result.observations().getFirst().detail());
        }
        var result = run(() -> { var snapshot = source.snapshot(); Files.delete(path); return snapshot; }, token.root(), first.knowledge());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, result.discoveryState());
        assertEquals(first.knowledge().records(), result.knowledge().records());
    }
    @Test void frozenSymlinkReplacementIsIncompleteAndCommitStillRequired() throws Exception {
        Path dir = Files.createDirectory(root.resolve("objects-v1")); var token = fixture(TOKEN);
        Path path = dir.resolve(token.id().filename()); Files.write(path, token.bytes());
        var source = new NioDiscoverySource(root);
        var failed = DiscoveryCoordinator.discover(source, token.root(), DurableKnowledgeState.establishedEmpty(),
                observation -> DurableKnowledgeState.PersistenceResult.FAILED);
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, failed.discoveryState());
        var replaced = run(() -> {
            var snapshot = source.snapshot(); Files.delete(path); Files.createSymbolicLink(path, root.resolve("elsewhere"));
            return snapshot;
        }, token.root(), DurableKnowledgeState.establishedEmpty());
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE, replaced.discoveryState());
        assertEquals(ObjectDiscovery.Classification.UNAVAILABLE, replaced.observations().getFirst().classification());
    }
    @Test void authenticatedPaddingAndIdentityFailuresRetainKnownNode() throws Exception {
        var token = fixture(TOKEN); Path dir = Files.createDirectory(root.resolve("objects-v1"));
        Path path = dir.resolve(token.id().filename()); Files.write(path, token.bytes());
        var source = new NioDiscoverySource(root);
        var known = run(source, token.root(), DurableKnowledgeState.establishedEmpty()).knowledge();
        byte[] key = CryptoSupport.objectKey(CryptoSupport.objectRoot(CryptoSupport.extract(token.root())), token.id());
        var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        var secret = new javax.crypto.spec.SecretKeySpec(key, "AES");
        var parameters = new javax.crypto.spec.GCMParameterSpec(128, EnvelopeReader.nonce(token.id()));
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secret, parameters);
        cipher.updateAAD(EnvelopeReader.aad(token.id()));
        byte[] padded = cipher.doFinal(token.bytes());
        for (int offset : List.of(1007, 2)) {
            byte[] altered = padded.clone(); altered[offset] ^= 1;
            // Test-only corruption fixture, not a protocol writer or OTP generator.
            cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secret, parameters);
            cipher.updateAAD(EnvelopeReader.aad(token.id()));
            Files.write(path, cipher.doFinal(altered));
            var result = run(source, token.root(), known);
            assertEquals(offset == 1007 ? ObjectDiscovery.Detail.PADDING : ObjectDiscovery.Detail.OBJECT_ID,
                    result.observations().getFirst().detail());
            assertEquals(known.records(), result.knowledge().records());
            assertEquals(known.continuity(), result.knowledge().continuity());
            assertTrue(result.readable().evidence().isEmpty());
            assertEquals(DiscoveryState.READY, result.discoveryState());
        }
    }
}
