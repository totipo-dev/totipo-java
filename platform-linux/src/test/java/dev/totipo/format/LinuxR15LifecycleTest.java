package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;

class LinuxR15LifecycleTest {
    @TempDir(factory=LocalStorageTempDirectory.class) Path directory;
    static TokenValue value(int status,String account,int secret){return new TokenValue(status,"Example",account,
            new TokenValue.Credential(1,6,30,new SecurityBytes(new byte[]{(byte)secret},1)));}
    static TokenUpdatePublication.Context context(SnapshotSession session){return new TokenUpdatePublication.Context(new InitialDeviceAdvertisement.Context(session));}
    static InitialTokenPublication.Result edit(byte[] root,SnapshotSession session,DeviceIdentityResult identity,SecurityBytes token,TokenValue value,
            TokenUpdatePublication.Intent intent,V1ObjectPublicationStore store,List<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> receipts){
        return TokenUpdatePublication.publish(root,()->context(session),identity,token,value,new byte[8],intent,store,receipts);
    }
    @Test void fullLifecycleRestartDisappearanceAndConflicts() throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        byte[] password=CryptoSupport.ascii("password");byte[] root;
        ObjectId deviceObject;SecurityBytes token;
        try(var binding=LinuxVaultBindingStore.open(local);var vault=NioVaultBootstrapStorage.open(sync,LinuxDurability.open());
            var keys=LinuxDeviceProvenanceKeyStore.open(local);var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())){
            try(var result=new VaultLifecycle(vault,binding,new NioDiscoverySource(sync)).createNew(password)){
                assertEquals(VaultLifecycleResult.Status.CREATED_ESTABLISHED,result.status());root=result.root();
            }
            var session=new SnapshotSession(new SecurityBytes(binding.read().bytes(),32));
            try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)){
                assertEquals(DeviceIdentityResult.Status.CREATED_BOUND,identity.status());
                var device=InitialDeviceAdvertisement.publish(root,()->new InitialDeviceAdvertisement.Context(session),identity,"Linux",new byte[8],store);
                assertEquals(InitialDeviceAdvertisement.Status.PUBLISHED,device.status());deviceObject=device.objectId();
                var first=InitialTokenPublication.publish(root,()->new InitialDeviceAdvertisement.Context(session),identity,value(1,"alice",1),new byte[8],store,List.of(device.receipt()));
                assertEquals(PUBLISHED_SUCCESS_READY,first.status());token=first.receipt().tokenId();
                assertNotNull(session.snapshot().object(first.receipt().objectId()));
            }
        }
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var identity=DeviceIdentityLifecycle.loadExisting(binding.read(),keys);var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())){
            var session=new SnapshotSession(new SecurityBytes(binding.read().bytes(),32));
            assertTrue(session.snapshot().objects().isEmpty());
            session.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
            assertEquals(2,session.snapshot().objects().size());
            var deviceReceipt=DeviceAdvertisementReader.acknowledge(deviceObject,Files.readAllBytes(sync.resolve("objects-v1").resolve(deviceObject.filename())),root,store);
            assertNotNull(deviceReceipt);var receipts=List.of(deviceReceipt);
            var a=session.snapshot();
            var changed=edit(root,session,identity,token,value(1,"edited",1),TokenUpdatePublication.Intent.ORDINARY,store,receipts);
            assertEquals(PUBLISHED_SUCCESS_READY,changed.status());
            var rotation=edit(root,session,identity,token,value(1,"edited",2),TokenUpdatePublication.Intent.ORDINARY,store,receipts);
            assertEquals(PUBLISHED_SUCCESS_READY,rotation.status());
            assertEquals(PUBLISHED_SUCCESS_READY,edit(root,session,identity,token,value(2,"edited",2),TokenUpdatePublication.Intent.ORDINARY,store,receipts).status());
            assertFalse(new TokenOperationPolicy(session.snapshot(),token).ordinaryUse().eligible());
            assertEquals(RESTORATION_INTENT_REQUIRED,edit(root,session,identity,token,value(1,"edited",2),TokenUpdatePublication.Intent.ORDINARY,store,receipts).status());
            var restored=edit(root,session,identity,token,value(1,"edited",2),TokenUpdatePublication.Intent.RESTORE,store,receipts);
            assertEquals(PUBLISHED_SUCCESS_READY,restored.status());
            // Independent snapshot creates equal concurrent siblings, then converges all heads.
            var base=session.snapshot();
            var siblingSession=new SnapshotSession(session.binding());siblingSession.replace(base);
            var b=edit(root,session,identity,token,value(1,"equal",3),TokenUpdatePublication.Intent.ORDINARY,store,receipts);
            var c=edit(root,siblingSession,identity,token,value(1,"equal",3),TokenUpdatePublication.Intent.ORDINARY,store,receipts);
            assertNotEquals(b.receipt().objectId(),c.receipt().objectId());
            session.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
            assertEquals(2,session.snapshot().topology().currentTokenHeads(token).size());
            assertTrue(new TokenOperationPolicy(session.snapshot(),token).ordinaryUse().eligible());
            var converged=edit(root,session,identity,token,value(1,"equal",3),TokenUpdatePublication.Intent.ORDINARY,store,receipts);
            var merged=(AcceptedToken)session.snapshot().object(converged.receipt().objectId());
            assertEquals(Set.of(b.receipt().objectId(),c.receipt().objectId()),Set.copyOf(merged.parents()));
            // Hidden history after publication remains valid concurrent history.
            siblingSession.replace(a);
            var hidden=edit(root,siblingSession,identity,token,value(1,"hidden",4),TokenUpdatePublication.Intent.ORDINARY,store,receipts);
            assertEquals(PUBLISHED_SUCCESS_READY,hidden.status());
            session.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
            assertEquals(CONFIRMATION_REQUIRED_CONFLICT,edit(root,session,identity,token,value(1,"chosen",5),TokenUpdatePublication.Intent.ORDINARY,store,receipts).status());
            var chosen=value(1,"chosen",5);var consent=TokenResolutionConfirmation.prepare(root,context(session),identity,token,chosen,TokenUpdatePublication.Intent.ORDINARY);
            var resolved=TokenUpdatePublication.publishConfirmed(root,()->context(session),identity,token,chosen,new byte[8],TokenUpdatePublication.Intent.ORDINARY,consent.confirmation(),store,receipts);
            assertEquals(PUBLISHED_SUCCESS_READY,resolved.status());
            // Remove B from synchronized storage: the next pass contains only currently present evidence.
            Files.delete(sync.resolve("objects-v1").resolve(resolved.receipt().objectId().filename()));
            session.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
            assertNull(session.snapshot().object(resolved.receipt().objectId()));
            assertEquals(CurrentTokenValueState.CONFLICT,new TokenOperationPolicy(session.snapshot(),token).current().state());
            // Restrict synchronized history to original A and DEVICE, then restart with no memory.
            try(var files=Files.list(sync.resolve("objects-v1"))){for(var file:files.toList())if(!a.objects().containsKey(ObjectId.fromFilename(file.getFileName().toString())))Files.delete(file);}
            var restart=new SnapshotSession(session.binding());restart.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
            assertEquals(a.objects(),restart.snapshot().objects());assertTrue(new TokenOperationPolicy(restart.snapshot(),token).ordinaryUse().eligible());
            assertEquals(PUBLISHED_SUCCESS_READY,edit(root,restart,identity,token,value(1,"after restart",6),TokenUpdatePublication.Intent.ORDINARY,store,receipts).status());
        }finally{Arrays.fill(root,(byte)0);}
    }
    @Test void ambiguousInstalledAndNotInstalledRetryWithoutFence() throws Exception {
        for(boolean installed:List.of(false,true)){
            Path sync=Files.createDirectory(directory.resolve("sync"+installed)),local=Files.createDirectory(directory.resolve("local"+installed));
            byte[] root=new byte[32];
            try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local)){
                byte[] anchor=CryptoSupport.hmac(root,CryptoSupport.ascii("totipo/v1/local-vault-binding"));binding.create(anchor);
                try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)){
                    var session=new SnapshotSession(new SecurityBytes(anchor,32));var faults=new ObjectPublicationFaults(LinuxDurability.open());
                    faults.fail=installed?"directory-sync":"before-link";
                    try(var store=faults.open(sync)){
                        var failed=InitialTokenPublication.publish(root,()->new InitialDeviceAdvertisement.Context(session),identity,value(1,"retry",1),new byte[8],store,List.of());
                        assertEquals(PUBLICATION_INCOMPLETE,failed.status());assertTrue(session.snapshot().objects().isEmpty());
                        var discovered=DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot();
                        assertEquals(installed?1:0,discovered.objects().size());
                        faults.fail="";
                        var retried=InitialTokenPublication.publish(root,()->new InitialDeviceAdvertisement.Context(session),identity,value(1,"retry",1),new byte[8],store,List.of());
                        assertEquals(PUBLISHED_DEVICE_REQUIRED,retried.status());
                        assertEquals(installed?2:1,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot().objects().size());
                        var id=retried.receipt().objectId();byte[] exact=Files.readAllBytes(sync.resolve("objects-v1").resolve(id.filename()));
                        assertEquals(V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT,store.publish(id,exact));
                    }
                }
            }
        }
    }
    @Test void noAdvisoryHistoryAcrossActualProcessExitThenLateSibling() throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        byte[] root=new byte[32];byte[] anchor=CryptoSupport.hmac(root,CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            binding.create(anchor);
            try(var identity=DeviceIdentityLifecycle.createNew(binding.read(),keys)) {
                var firstSession=new SnapshotSession(new SecurityBytes(anchor,32));
                var a=InitialTokenPublication.publish(root,()->new InitialDeviceAdvertisement.Context(firstSession),identity,value(1,"a",1),new byte[8],store,List.of());
                var token=a.receipt().tokenId();
                // A separate process accepts A and exits with no graph persistence API.
                var locations=new ArrayList<String>();
                for(var type:List.of(SnapshotProbe.class,NioDiscoverySource.class,DiscoverySource.class))
                    locations.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
                var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),
                        "--illegal-native-access=deny","-cp",String.join(java.io.File.pathSeparator,locations),SnapshotProbe.class.getName(),
                        sync.toString(),a.receipt().objectId().filename()).redirectErrorStream(true).start();
                try {
                    assertTrue(child.waitFor(20,java.util.concurrent.TimeUnit.SECONDS));
                    assertEquals(0,child.exitValue(),new String(child.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
                } finally { child.destroyForcibly(); }
                var restarted=new SnapshotSession(new SecurityBytes(binding.read().bytes(),32));
                assertTrue(restarted.snapshot().objects().isEmpty());
                restarted.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
                var planning=restarted.snapshot();
                var b=edit(root,restarted,identity,token,value(1,"b",2),TokenUpdatePublication.Intent.ORDINARY,store,List.of());
                assertEquals(PUBLISHED_DEVICE_REQUIRED,b.status());
                var remote=new SnapshotSession(restarted.binding());remote.replace(planning);
                var c=edit(root,remote,identity,token,value(1,"c",3),TokenUpdatePublication.Intent.ORDINARY,store,List.of());
                restarted.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),root).snapshot());
                assertEquals(Set.of(b.receipt().objectId(),c.receipt().objectId()),restarted.snapshot().topology().currentTokenHeads(token));
                assertEquals(List.of(a.receipt().objectId()),((AcceptedToken)restarted.snapshot().object(b.receipt().objectId())).parents());
                assertEquals(CurrentTokenValueState.CONFLICT,new TokenOperationPolicy(restarted.snapshot(),token).current().state());
                assertTrue(Arrays.stream(CandidateWarning.values()).noneMatch(w->w.name().startsWith("HISTORY_")));
            }
        }
    }
    public static final class SnapshotProbe {
        public static void main(String[] args) {
            var snapshot=DiscoveryCoordinator.discover(new NioDiscoverySource(Path.of(args[0])),new byte[32]).snapshot();
            var object=snapshot.object(ObjectId.fromFilename(args[1]));
            if(snapshot.objects().size()!=1 || !(object instanceof AcceptedToken token)
                    || !new TokenOperationPolicy(snapshot,token.tokenId()).ordinaryUse().eligible())throw new AssertionError("Fresh discovery");
        }
    }
}
