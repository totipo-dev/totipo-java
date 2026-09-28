package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LinuxDevicePresentationTest {
    @TempDir(factory=LocalStorageTempDirectory.class) Path directory;
    static final byte[] ROOT=new byte[32];
    static final byte[] BINDING=CryptoSupport.hmac(ROOT,CryptoSupport.ascii("totipo/v1/local-vault-binding"));
    static SnapshotSession discover(Path sync) {
        var session=new SnapshotSession(new SecurityBytes(BINDING,32));
        session.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT).snapshot());return session;
    }
    static AcceptedDevice check(Path sync, SnapshotSession session, DevicePresentationUpdate.Result result,
                                DeviceIdentityResult identity, String name, Set<ObjectId> parents) throws Exception {
        assertEquals(DevicePresentationUpdate.Status.PUBLISHED,result.status());
        byte[] bytes=Files.readAllBytes(sync.resolve("objects-v1").resolve(result.objectId().filename()));
        var opened=EnvelopeReader.open(result.objectId().filename(),bytes,ROOT);
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE,opened.status());
        var assertion=AssertionValidator.validate(opened);assertEquals(AssertionValidator.Status.ASSERTION_VALID,assertion.status());
        assertEquals(ProvenanceStatus.VERIFIED,ProvenanceEvaluator.evaluate(assertion.object(),ROOT,VerificationKeyMaterial.keys()));
        var node=(AcceptedDevice)AuthenticatedObservation.supported(assertion.object(),ProvenanceStatus.VERIFIED).record();
        assertEquals(parents,Set.copyOf(node.parents()));assertEquals(name,node.displayName());
        assertArrayEquals(identity.deviceId(),node.deviceId().bytes());assertArrayEquals(identity.publicKeyX963(),node.publicKeyX963().bytes());
        assertEquals(java.math.BigInteger.ZERO,node.authorTime());assertEquals(node,session.snapshot().object(node.objectId()));return node;
    }
    @Test void sequentialRenameReopensCustodyAndFreshProcessDiscoversPresentation() throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        ObjectId renamed;byte[] publicKey;
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            binding.create(BINDING);
            try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)) {
                var session=discover(sync);var initial=InitialDeviceAdvertisement.publish(ROOT,()->new InitialDeviceAdvertisement.Context(session),identity,"phone",new byte[8],store);
                assertEquals(InitialDeviceAdvertisement.Status.PUBLISHED,initial.status());
                session.replace(discover(sync).snapshot());
                var result=DevicePresentationUpdate.publish(ROOT,session,identity,"daily phone",new byte[8],store);
                check(sync,session,result,identity,"daily phone",Set.of(initial.objectId()));renamed=result.objectId();publicKey=identity.publicKeyX963();
            }
        }
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var identity=DeviceIdentityLifecycle.loadExisting(binding.read(),keys)) {
            assertArrayEquals(publicKey,identity.publicKeyX963());var session=discover(sync);
            assertEquals(Set.of("daily phone"),DevicePresentation.evaluate(session.snapshot(),new SecurityBytes(identity.deviceId(),32)).names());
        }
        var locations=new ArrayList<String>();
        for(var type:List.of(Probe.class,NioDiscoverySource.class,DiscoverySource.class))
            locations.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"--illegal-native-access=deny",
                "-cp",String.join(java.io.File.pathSeparator,locations),Probe.class.getName(),sync.toString(),renamed.filename())
                .redirectErrorStream(true).start();
        try { assertTrue(child.waitFor(20,java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(0,child.exitValue(),new String(child.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
        } finally {child.destroyForcibly();}
    }
    @Test void forkAndCryptographicallyRejectedNameConverge() throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            binding.create(BINDING);
            try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)) {
                var session=discover(sync);var initial=InitialDeviceAdvertisement.publish(ROOT,()->new InitialDeviceAdvertisement.Context(session),identity,"phone",new byte[8],store);
                var base=session.snapshot();var other=new SnapshotSession(session.binding());other.replace(base);
                var b=DevicePresentationUpdate.publish(ROOT,session,identity,"phone",new byte[8],store);
                check(sync,session,b,identity,"phone",Set.of(initial.objectId()));
                var c=DevicePresentationUpdate.publish(ROOT,other,identity,"pixel",new byte[8],store);
                check(sync,other,c,identity,"pixel",Set.of(initial.objectId()));
                // Valid vault-authenticated assertion with explicit zero-length (rejected) signature.
                byte[] signed=DeviceWriter.signed(ROOT,identity,"hostile",new byte[8],List.of(initial.objectId()));
                var parsed=V1PlaintextParser.parse(signed).plaintext();
                byte[] unsigned=Arrays.copyOf(signed,signed.length-4-parsed.signature().length);
                var rejected=V1EnvelopeWriter.seal(ROOT,CryptoSupport.join(unsigned,new TlvWriter().field(0xff01,new byte[0]).bytes()));
                store.publish(rejected.id(),rejected.bytes());session.replace(discover(sync).snapshot());
                assertEquals(ProvenanceStatus.REJECTED,((AcceptedDevice)session.snapshot().object(rejected.id())).provenance());
                var device=new SecurityBytes(identity.deviceId(),32);
                assertEquals(Set.of("phone","pixel"),DevicePresentation.evaluate(session.snapshot(),device).names());
                var result=DevicePresentationUpdate.publish(ROOT,session,identity,"main phone",new byte[8],store);
                check(sync,session,result,identity,"main phone",Set.of(b.objectId(),c.objectId(),rejected.id()));
                var restart=discover(sync);assertEquals(Set.of(result.objectId()),restart.snapshot().topology().currentDeviceHeads(device));
                for(var ancestor:List.of(b.objectId(),c.objectId(),rejected.id()))assertTrue(restart.snapshot().topology().ancestor(ancestor,result.objectId()));
                assertEquals(Set.of("main phone"),DevicePresentation.evaluate(restart.snapshot(),device).names());
            }
        }
    }
    @Test void branchArrivingBetweenPlanAndPublishKeepsFixedParents() throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            binding.create(BINDING);
            try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)) {
                var session=discover(sync);var a=InitialDeviceAdvertisement.publish(ROOT,()->new InitialDeviceAdvertisement.Context(session),identity,"a",new byte[8],store);
                var remote=new SnapshotSession(session.binding());remote.replace(session.snapshot());
                ObjectId[] b={null};
                var result=DevicePresentationUpdate.publish(ROOT,session,identity,"local",new byte[8],store,()->{
                    var branch=DevicePresentationUpdate.publish(ROOT,remote,identity,"remote",new byte[8],store);b[0]=branch.objectId();
                    try {check(sync,remote,branch,identity,"remote",Set.of(a.objectId()));}catch(Exception e){throw new AssertionError(e);}
                    session.replace(discover(sync).snapshot());
                });
                check(sync,session,result,identity,"local",Set.of(a.objectId()));
                var restart=discover(sync);var device=new SecurityBytes(identity.deviceId(),32);
                assertEquals(Set.of(b[0],result.objectId()),restart.snapshot().topology().currentDeviceHeads(device));
                assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(restart.snapshot(),device).state());
            }
        }
    }
    @Test void postInstallFailureIsIncompleteUntilDiscoveryAndDoesNotFenceRetry() throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local)) {
            binding.create(BINDING);
            try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)) {
                var faults=new ObjectPublicationFaults(LinuxDurability.open());
                try(var store=faults.open(sync)) {
                    var session=discover(sync);var a=InitialDeviceAdvertisement.publish(ROOT,()->new InitialDeviceAdvertisement.Context(session),identity,"a",new byte[8],store);
                    var before=session.snapshot();faults.fail="directory-sync";
                    var failed=DevicePresentationUpdate.publish(ROOT,session,identity,"installed",new byte[8],store);
                    assertEquals(DevicePresentationUpdate.Status.PUBLICATION_INCOMPLETE,failed.status());assertSame(before,session.snapshot());
                    var restart=discover(sync);var device=new SecurityBytes(identity.deviceId(),32);
                    assertEquals(Set.of("installed"),DevicePresentation.evaluate(restart.snapshot(),device).names());
                    var installed=restart.snapshot().topology().currentDeviceHeads(device).iterator().next();
                    check(sync,restart,new DevicePresentationUpdate.Result(DevicePresentationUpdate.Status.PUBLISHED,installed),identity,"installed",Set.of(a.objectId()));
                    faults.fail="";
                    var retry=DevicePresentationUpdate.publish(ROOT,session,identity,"retry",new byte[8],store);
                    check(sync,session,retry,identity,"retry",Set.of(a.objectId()));
                    assertEquals(2,discover(sync).snapshot().topology().currentDeviceHeads(device).size());
                }
            }
        }
    }
    public static final class Probe {
        public static void main(String[] args) {
            var session=discover(Path.of(args[0]));var id=ObjectId.fromFilename(args[1]);var device=(AcceptedDevice)session.snapshot().object(id);
            if(!session.snapshot().topology().currentDeviceHeads(device.deviceId()).equals(Set.of(id))
                    || !DevicePresentation.evaluate(session.snapshot(),device.deviceId()).names().equals(Set.of("daily phone")))throw new AssertionError("Fresh process presentation");
        }
    }
}
