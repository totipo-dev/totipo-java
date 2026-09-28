package dev.totipo.format;

import dev.totipo.conformance.VectorCaseLoader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/** Test storage environment: never interprets virtual paths as host paths. */
final class DiscoveryFixtures implements DiscoverySource {
    static final String TOKEN = "v1.crypto.token-root.001";
    static final String CHILD = "v1.crypto.token-child.001";
    static final String FUTURE = "v1.crypto.future-token-opaque.001";
    record ObjectBytes(ObjectId id, byte[] bytes, byte[] root) {
        @Override public String toString() { return "ObjectBytes[redacted]"; }
    }
    record Entry(String kind, Supplier<byte[]> content) {}
    final Map<String, Entry> entries = new LinkedHashMap<>();
    final List<String> reads = new ArrayList<>();
    SnapshotIssue issue = SnapshotIssue.NONE;
    String namespace = "directory";

    void put(ObjectBytes object) { put(object.id(), object.bytes()); }
    void put(ObjectId id, byte[] bytes) {
        entries.put("objects-v1/" + id.filename(), new Entry("regular", () -> bytes.clone()));
    }
    void remove(ObjectId id) { entries.remove("objects-v1/" + id.filename()); }

    @Override public Snapshot snapshot() {
        var candidates = new ArrayList<Candidate>();
        if (namespace.equals("absent")) { return new Snapshot(candidates, issue); }
        if (!namespace.equals("directory")) { return new Snapshot(candidates, SnapshotIssue.UNSAFE_NAMESPACE); }
        entries.forEach((path, entry) -> {
            if (!path.startsWith("objects-v1/") || !entry.kind().equals("regular")) { return; }
            ObjectId id;
            try { id = ObjectId.fromFilename(path.substring("objects-v1/".length())); }
            catch (IllegalArgumentException e) { return; }
            candidates.add(new Candidate(id, () -> {
                reads.add(path);
                var current = entries.get(path);
                if (current == null || !current.kind().equals("regular") || current.content() == null) {
                    throw new IOException("Unavailable test entry");
                }
                return Channels.newChannel(new ByteArrayInputStream(current.content().get()));
            }));
        });
        return new Snapshot(candidates, issue);
    }

    static ObjectBytes fixture(String id) throws IOException {
        var all = new ArrayList<>(VectorCaseLoader.cryptoCases());
        all.addAll(VectorCaseLoader.routingCases());
        var c = all.stream().filter(v -> v.id().equals(id)).findFirst().orElseThrow();
        return new ObjectBytes(ObjectId.fromFilename(c.data().field("crypto").field("object_id").string()),
                c.data().field("crypto").field("object_hex").hex(), c.data().field("root_hex").hex());
    }

    static ObjectBytes semantic(byte[] root, byte[] semantic) throws Exception {
        byte[] prk = CryptoSupport.extract(root);
        var id = ObjectId.compute(CryptoSupport.idKey(prk), semantic);
        byte[] key = CryptoSupport.objectKey(CryptoSupport.objectRoot(prk), id);
        return new ObjectBytes(id, CryptoVectorTest.encrypt(key, EnvelopeReader.nonce(id),
                EnvelopeReader.aad(id), CryptoVectorTest.padded(semantic)), root);
    }

    static DiscoveryFixtures vector(VectorCaseLoader.Node storage) throws IOException {
        var source = new DiscoveryFixtures();
        source.namespace = storage.field("namespace_kind").string();
        for (var e : storage.field("entries").array()) {
            String path = e.field("path").string();
            if (source.entries.put(path, new Entry(e.field("kind").string(), () -> {
                // Called only after selection. Ignored virtual entries never resolve fixture content.
                try {
                    if (e.has("fixture_case")) { return fixture(e.field("fixture_case").string()).bytes(); }
                    if (e.has("data_hex")) { return e.field("data_hex").hex(); }
                    return new byte[e.has("zero_bytes") ? e.field("zero_bytes").integer().intValueExact() : 0];
                } catch (IOException ex) { throw new AssertionError(ex); }
            })) != null) { throw new AssertionError("Duplicate virtual path"); }
        }
        return source;
    }
}
