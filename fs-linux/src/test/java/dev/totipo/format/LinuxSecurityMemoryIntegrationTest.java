package dev.totipo.format;

import dev.totipo.fs.linux.LinuxSecurityMemoryStorage;
import dev.totipo.fs.linux.NioDiscoverySource;
import dev.totipo.fs.linux.StorageFaults;
import dev.totipo.fs.linux.LocalStorageTempDirectory;
import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static dev.totipo.format.SecurityMemoryCrashProcess.*;
import static dev.totipo.format.NioTestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class LinuxSecurityMemoryIntegrationTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path journal(Path p) { return p.resolve("security-memory-v1.bin"); }
    byte[] binding() throws Exception {
        Path path=Path.of(System.getProperty("totipo.test.snapshot"),"vectors/cases/bootstrap/v1.bootstrap.ascii.001.json");
        var fields=new HashMap<String,String>();
        try(var parser=new com.fasterxml.jackson.core.JsonFactory().createParser(path.toFile())) {
            while(parser.nextToken()!=null) if(parser.currentToken()==com.fasterxml.jackson.core.JsonToken.VALUE_STRING)
                fields.put(parser.currentName(),parser.getText());
        }
        byte[] root=HexFormat.of().parseHex(fields.get("root_hex"));
        byte[] binding=CryptoSupport.hmac(root,CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        assertArrayEquals(HexFormat.of().parseHex(fields.get("binding_hex")),binding); return binding;
    }
    SecurityMemorySession established(LinuxSecurityMemoryStorage storage) throws Exception {
        var s=SecurityMemorySession.initializeNew(storage); assertTrue(s.establishFirstOpen(binding())); return s;
    }
    SecurityMemoryJournal.Replay replay(Path p) throws Exception {
        var barriers=new StorageFaults();
        try(var storage=barriers.open(p)) {
            assertEquals(List.of("journal","directory"),barriers.adoption);
            assertEquals(0,barriers.forces);
            try(var stream=storage.openRead()) { return SecurityMemoryJournal.replay(stream); }
        }
    }
    Process child(String command,Path p,String arg) throws Exception {
        var locations=new ArrayList<String>();
        for(Class<?> c:List.of(SecurityMemoryCrashProcess.class,LinuxSecurityMemoryStorage.class,SecurityMemoryStorage.class))
            locations.add(Path.of(c.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        return new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED","--illegal-native-access=deny","-cp",
                String.join(File.pathSeparator,locations),SecurityMemoryCrashProcess.class.getName(),command,p.toString(),arg)
                .redirectErrorStream(true).start();
    }
    void halt(String command,Path p,String arg) throws Exception {
        var process=child(command,p,arg);
        try {
            assertTrue(process.waitFor(20,TimeUnit.SECONDS));
            assertEquals(0,process.exitValue(),new String(process.getInputStream().readAllBytes(),StandardCharsets.UTF_8));
        } finally { process.destroyForcibly(); }
    }
    void halt(String command,Path p) throws Exception { halt(command,p,HexFormat.of().formatHex(binding())); }
    @Test void initializePendingEstablishAndDirectFirstOpenSurviveHalt() throws Exception {
        halt("initialize",dir);
        assertArrayEquals(SecurityMemoryJournal.header(),Files.readAllBytes(journal(dir)));
        assertEquals(LocalEstablishment.Phase.UNESTABLISHED,replay(dir).establishment().phase());
        halt("pending",dir); assertEquals(LocalEstablishment.Phase.PENDING,replay(dir).establishment().phase());
        assertArrayEquals(binding(),replay(dir).establishment().binding().bytes());
        // Canonical publication/authentication is modeled externally; this backend never writes VAULT.
        halt("establish",dir); assertEquals(LocalEstablishment.Phase.ESTABLISHED,replay(dir).establishment().phase());
        assertArrayEquals(binding(),replay(dir).establishment().binding().bytes());
        Path first=Files.createDirectory(dir.resolve("first")); halt("initialize",first); halt("first",first);
        assertArrayEquals(binding(),replay(first).establishment().binding().bytes());
        assertEquals(LocalEstablishment.Phase.ESTABLISHED,replay(first).establishment().phase());
    }
    @Test void appendMultipleCommitsAndIntegrityTransitionsSurviveHalt() throws Exception {
        try(var storage=LinuxSecurityMemoryStorage.open(dir)) { established(storage); }
        halt("append",dir); assertEquals(token(1),replay(dir).knowledge().record(id(1)));
        for(String command:List.of("multiple","unknown","cycle")) {
            Path p=Files.createDirectory(dir.resolve(command));
            try(var storage=LinuxSecurityMemoryStorage.open(p)) {
                if(command.equals("multiple")) SecurityMemorySession.initializeNew(storage); else established(storage);
            }
            halt(command,p); var r=replay(p); assertEquals(SecurityMemoryJournal.Status.CLEAN,r.status());
            if(command.equals("multiple")) assertEquals(4,r.knowledge().size());
            else assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN,r.knowledge().continuity());
            if(command.equals("cycle")) {
                assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE,new GraphTopology(r.knowledge()).integrity());
                assertEquals(3,r.sequence()); // establishment + two nodes, no redundant marker
            }
        }
    }
    @Test void crossProcessLockRejectsPromptlyAndTerminationReleases() throws Exception {
        var process=child("hold",dir,"");
        try(var executor=Executors.newSingleThreadExecutor()) {
            try {
                var ready=executor.submit(()->new BufferedReader(new InputStreamReader(process.getInputStream(),StandardCharsets.UTF_8)).readLine());
                assertEquals("READY",ready.get(10,TimeUnit.SECONDS));
                var blocked=child("initialize",dir,"");
                try {
                    assertTrue(blocked.waitFor(10,TimeUnit.SECONDS)); assertNotEquals(0,blocked.exitValue());
                    assertTrue(new String(blocked.getInputStream().readAllBytes(),StandardCharsets.UTF_8).contains("STORAGE_LOCKED"));
                } finally { blocked.destroyForcibly(); }
                assertFalse(Files.exists(journal(dir)));
                assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(dir));
                process.destroyForcibly(); assertTrue(process.waitFor(10,TimeUnit.SECONDS));
                halt("initialize",dir); assertEquals(SecurityMemoryJournal.Status.CLEAN,replay(dir).status());
                assertTrue(Files.exists(dir.resolve("security-memory.lock")));
            } finally { process.destroyForcibly(); }
        }
    }
    @Test void partialAppendReopenPreservesTailAndExplicitRepairSurvivesHalt() throws Exception {
        var faults=new StorageFaults(); long verified;
        try(var storage=faults.open(dir)) {
            var session=established(storage); session.commitRecord(token(1)); verified=session.head().verifiedBytes();
            faults.partialWrite=true;
            assertEquals(DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED,session.commitRecord(token(2)).outcome());
            assertNull(session.knowledge().record(id(2)));
        }
        byte[] before=Files.readAllBytes(journal(dir));
        var r=replay(dir); assertEquals(SecurityMemoryJournal.Status.INCOMPLETE_TAIL,r.status());
        assertEquals(verified,r.verifiedBytes()); assertArrayEquals(before,Files.readAllBytes(journal(dir)));
        halt("truncate",dir,Long.toString(r.verifiedBytes()));
        assertEquals(verified,Files.size(journal(dir))); assertEquals(SecurityMemoryJournal.Status.CLEAN,replay(dir).status());
        assertEquals(1,replay(dir).knowledge().size());
    }
    @Test void completeFrameAfterFailedForceIsAdoptedOnlyAfterReopen() throws Exception {
        var faults=new StorageFaults();
        try(var storage=faults.open(dir)) {
            var s=established(storage); faults.failForce=true;
            assertEquals(DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED,s.commitRecord(token(1)).outcome());
            assertNull(s.knowledge().record(id(1))); assertThrows(IOException.class,storage::openRead);
        }
        assertEquals(token(1),replay(dir).knowledge().record(id(1)));
    }
    @Test void failedInitializationAndTruncateForceRecoverActualState() throws Exception {
        var faults=new StorageFaults(); faults.failForce=true;
        try(var storage=faults.open(dir)) {
            assertThrows(IOException.class,()->SecurityMemorySession.initializeNew(storage));
        }
        assertEquals(SecurityMemoryJournal.Status.CLEAN,replay(dir).status());
        faults=new StorageFaults();
        try(var storage=faults.open(dir)) {
            var s=SecurityMemorySession.open(storage); assertTrue(s.establishFirstOpen(binding()));
            long offset=s.head().verifiedBytes();
            byte[] frame=SecurityMemoryJournal.frame(s.head().sequence()+1,s.head().digest(),
                    SecurityMemoryJournal.TOKEN,SecurityMemoryJournal.encode(token(1)));
            storage.appendDurably(Arrays.copyOf(frame,55));
            var broken=SecurityMemorySession.open(storage); assertEquals(offset,broken.head().verifiedBytes());
            faults.failForce=true;
            assertThrows(IOException.class,()->storage.truncateDurably(broken.head().verifiedBytes()));
            assertThrows(IOException.class,storage::openRead);
        }
        assertEquals(SecurityMemoryJournal.Status.CLEAN,replay(dir).status()); assertEquals(0,replay(dir).knowledge().size());
    }
    @Test void failedSameJvmOpenDoesNotReleaseOwnersCrossProcessLock() throws Exception {
        try(var storage=LinuxSecurityMemoryStorage.open(dir)) {
            assertNull(storage.openRead());
            assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(dir));
            var other=child("initialize",dir,"");
            try {
                assertTrue(other.waitFor(10,TimeUnit.SECONDS)); assertNotEquals(0,other.exitValue());
                assertTrue(new String(other.getInputStream().readAllBytes(),StandardCharsets.UTF_8).contains("STORAGE_LOCKED"));
            } finally { other.destroyForcibly(); }
            assertFalse(Files.exists(journal(dir)));
        }
    }
    @Test void diskContainsOnlyCoreFramesAndNoTokenValueMaterial() throws Exception {
        var f=fixture(TOKEN);
        var observation=new ObjectDiscovery().classify(f.id(),f.bytes(),f.root());
        var value=observation.readable().value();
        try(var storage=LinuxSecurityMemoryStorage.open(dir)) {
            var s=established(storage); byte[] prefix=Files.readAllBytes(journal(dir));
            byte[] frame=SecurityMemoryJournal.frame(s.head().sequence()+1,s.head().digest(),
                    SecurityMemoryJournal.TOKEN,SecurityMemoryJournal.encode(observation.authenticated().record()));
            s.commit(observation.authenticated());
            assertArrayEquals(CryptoSupport.join(prefix,frame),Files.readAllBytes(journal(dir)));
            s.commitRecord(token(2)); s.commitRecord(token(3));
        }
        byte[] bytes=Files.readAllBytes(journal(dir));
        for(byte[] secret:List.of(value.issuer().getBytes(StandardCharsets.UTF_8),value.account().getBytes(StandardCharsets.UTF_8),
                value.credential().secret().bytes(),f.bytes(),f.root())) {
            assertTrue(secret.length>0); assertFalse(contains(bytes,secret));
        }
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(journal(dir)));
    }
    static boolean contains(byte[] haystack,byte[] needle) {
        outer:for(int i=0;i<=haystack.length-needle.length;i++) {
            for(int j=0;j<needle.length;j++) if(haystack[i+j]!=needle[j]) continue outer;
            return true;
        }
        return false;
    }
    @Test void malformedExistingStateIsNeverOverwrittenOrRepaired() throws Exception {
        byte[] wrong=SecurityMemoryJournal.header(); wrong[0]^=1;
        byte[] future=SecurityMemoryJournal.header(); future[11]=2;
        for(byte[] bytes:List.of(new byte[0],new byte[]{9,8,7},wrong,future,SecurityMemoryJournal.header())) {
            Path p=Files.createDirectory(dir.resolve("fixture"+UUID.randomUUID())); Files.write(journal(p),bytes);
            try(var s=LinuxSecurityMemoryStorage.open(p)) {
                assertThrows(IOException.class,()->s.initializeDurably(SecurityMemoryJournal.header()));
                try(var r=s.openRead()) { assertNotNull(r); assertArrayEquals(bytes,r.readAllBytes()); }
            }
            assertArrayEquals(bytes,Files.readAllBytes(journal(p)));
            assertEquals(Arrays.equals(bytes,SecurityMemoryJournal.header())?SecurityMemoryJournal.Status.CLEAN:
                    bytes==future?SecurityMemoryJournal.Status.UNSUPPORTED_LOCAL_FORMAT:SecurityMemoryJournal.Status.CORRUPT,replay(p).status());
        }
        try(var s=LinuxSecurityMemoryStorage.open(dir)) { var session=established(s);session.commitRecord(token(1));session.commitRecord(token(2)); }
        byte[] corrupt=Files.readAllBytes(journal(dir)); corrupt[60]^=1; Files.write(journal(dir),corrupt);
        assertEquals(SecurityMemoryJournal.Status.CORRUPT,replay(dir).status()); assertArrayEquals(corrupt,Files.readAllBytes(journal(dir)));
    }
    @Test void realDiscoveryDurablyCommitsThenRestartRequiresFreshReadableEvidence() throws Exception {
        Path local=Files.createDirectory(dir.resolve("local")); Path sync=Files.createDirectory(dir.resolve("sync"));
        Path objects=Files.createDirectory(sync.resolve("objects-v1")); var f=fixture(TOKEN);
        Files.write(objects.resolve(f.id().filename()),f.bytes());
        var source=new NioDiscoverySource(sync); DurableKnowledgeState prior;
        try(var storage=LinuxSecurityMemoryStorage.open(local)) {
            var s=established(storage); var result=DiscoveryCoordinator.discover(source,f.root(),s);
            assertEquals(DiscoveryState.READY,result.discoveryState()); prior=result.knowledge();
            assertTrue(policy(result,result.readable().get(f.id()).tokenId()).ordinaryUse().eligible());
            byte[] before=Files.readAllBytes(journal(local));
            assertEquals(DurableKnowledgeState.Outcome.UNCHANGED,s.commitRecord(prior.record(f.id())).outcome());
            assertArrayEquals(before,Files.readAllBytes(journal(local)));
        }
        try(var storage=LinuxSecurityMemoryStorage.open(local)) {
            var s=SecurityMemorySession.open(storage); assertEquals(prior.records(),s.knowledge().records());
            assertTrue(new CurrentReadableValues(new GraphTopology(s.knowledge()),List.of()).evidence().isEmpty());
            var result=DiscoveryCoordinator.discover(source,f.root(),s);
            assertEquals(DiscoveryState.READY,result.discoveryState());
            assertTrue(policy(result,result.readable().get(f.id()).tokenId()).ordinaryUse().eligible());
        }
    }
    @Test void discoveryFailureAndReclassificationNeverAuthorizeNewEvidence() throws Exception {
        Path sync=Files.createDirectory(dir.resolve("sync")); Path objects=Files.createDirectory(sync.resolve("objects-v1"));
        var f=fixture(TOKEN); Files.write(objects.resolve(f.id().filename()),f.bytes());
        for(boolean reclassify:new boolean[]{false,true}) {
            Path local=Files.createDirectory(dir.resolve("local"+reclassify)); var faults=new StorageFaults();
            try(var storage=faults.open(local)) {
                var s=established(storage);
                if(reclassify) s.commitRecord(new OpaqueUnscopedRecord(f.id(),new SecurityBytes(f.bytes(),1024)));
                byte[] before=Files.readAllBytes(journal(local)); int forces=faults.forces,writes=faults.writes;
                faults.failForce=true;
                if(reclassify) {
                    var scoped=new ObjectDiscovery().classify(f.id(),f.bytes(),f.root()).authenticated();
                    assertEquals(DurableKnowledgeState.Outcome.RECLASSIFICATION_REQUIRED,s.commit(scoped).outcome());
                }
                var result=DiscoveryCoordinator.discover(new NioDiscoverySource(sync),f.root(),s);
                assertEquals(DiscoveryState.PROCESSING_INCOMPLETE,result.discoveryState());
                assertTrue(result.readable().evidence().isEmpty());
                assertFalse(new VaultReadiness(result.knowledge(),result.discoveryState()).authoritativeVaultReady());
                if(reclassify) {
                    assertEquals(forces,faults.forces); assertEquals(writes,faults.writes);
                    assertArrayEquals(before,Files.readAllBytes(journal(local)));
                    assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN,s.knowledge().continuity());
                } else {
                    assertTrue(s.knowledge().knowledgePersistenceBlocked()); assertNull(s.knowledge().record(f.id()));
                    assertFalse(new VaultReadiness(s.knowledge(),result.discoveryState()).baseOperationSafe());
                }
            }
            if(reclassify) assertArrayEquals(f.bytes(),((OpaqueUnscopedRecord)replay(local).knowledge().record(f.id())).exactObjectBytes().bytes());
        }
    }
    @Test void largeJournalStreamsBoundedReadsAndAppendOnlyWritesOneFrame() throws Exception {
        var faults=new StorageFaults();
        try(var storage=faults.open(dir)) {
            var s=established(storage);
            // Distinct retained opaque records yield >2 MiB with only bounded per-frame encoding.
            for(int i=1;i<=2000;i++) s.commitRecord(new OpaqueUnscopedRecord(id(i),new SecurityBytes(new byte[1024],1024)));
            assertTrue(Files.size(journal(dir))>2_000_000);
            int writes=faults.writes, forces=faults.forces; long size=Files.size(journal(dir));
            s.commitRecord(token(3000));
            assertEquals(writes+1,faults.writes); assertEquals(forces+1,faults.forces);
            assertEquals(SecurityMemoryJournal.MIN_FRAME+SecurityMemoryJournal.encode(token(3000)).length,Files.size(journal(dir))-size);
        }
        try(var storage=LinuxSecurityMemoryStorage.open(dir);var input=storage.openRead()) {
            var bounded=new FilterInputStream(input) {
                @Override public byte[] readAllBytes() { throw new AssertionError("whole-file read"); }
                @Override public byte[] readNBytes(int n) throws IOException { assertTrue(n<=SecurityMemoryJournal.MAX_FRAME);return super.readNBytes(n); }
                @Override public int read(byte[] b,int o,int n) throws IOException { return super.read(b,o,Math.min(n,127)); }
            };
            assertEquals(2001,SecurityMemoryJournal.replay(bounded).knowledge().size());
        }
    }
}
