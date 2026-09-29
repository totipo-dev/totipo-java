package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.LinuxDevicePresentationTest.*;
import static dev.totipo.format.DevicePresentationUpdate.Status.*;

class LinuxDeviceFoldTest {
    @TempDir(factory=LocalStorageTempDirectory.class) Path directory;
    static final String NAME="n".repeat(256);
    static void seed(DeviceIdentityResult key,V1ObjectPublicationStore store,int count,boolean rejected)throws Exception {
        for(int i=0;i<count;i++) {
            byte[] semantic=DeviceWriter.signed(ROOT,key,"old "+i,new byte[8],List.of());
            if(rejected&&i==0) {
                int signature=V1PlaintextParser.parse(semantic).plaintext().signature().length;
                semantic=CryptoSupport.join(Arrays.copyOf(semantic,semantic.length-4-signature),new TlvWriter().field(0xff01,new byte[0]).bytes());
            }
            var object=V1EnvelopeWriter.seal(ROOT,semantic);store.publish(object.id(),object.bytes());
        }
    }
    @ParameterizedTest @ValueSource(strings={"wide","rejected","concurrent","ambiguous","exact"})
    void realFoldWithCustodyDiscoveryAndIndependentPublications(String scenario)throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        int count=scenario.equals("ambiguous")?33:15;
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local)) {
            binding.create(BINDING);
            var faults=new ObjectPublicationFaults(LinuxDurability.open());
            try(var key=DeviceIdentityLifecycle.createNew(binding.read(),keys);var store=faults.open(sync)) {
                seed(key,store,count,scenario.equals("rejected"));
                var s=discover(sync);var device=new SecurityBytes(key.deviceId(),32);
                var original=s.snapshot().topology().currentDeviceHeads(device);assertEquals(count,original.size());
                if(scenario.equals("rejected"))assertEquals(1,DevicePresentation.evaluate(s.snapshot(),device).inertHeads().size());
                var stages=new ArrayList<ObjectId>();var remote=new ObjectId[1];
                V1ObjectPublicationStore hooked=new V1ObjectPublicationStore() {
                    public PublicationResult publish(ObjectId id,byte[] bytes)throws IOException {
                        assertNull(s.snapshot().object(id));
                        for(var prior:stages)assertNotNull(s.snapshot().object(prior));
                        stages.add(id);
                        if(stages.size()==2&&scenario.equals("ambiguous"))faults.fail="directory-sync";
                        if(scenario.equals("exact"))assertEquals(PublicationResult.PUBLISHED_NEW,store.publish(id,bytes));
                        var ack=store.publish(id,bytes);
                        if(scenario.equals("exact"))assertEquals(PublicationResult.ALREADY_PRESENT_EXACT,ack);
                        return ack;
                    }
                    public void close(){}
                };
                var result=DevicePresentationUpdate.publish(ROOT,s,key,NAME,new byte[8],hooked,()->{
                    if(stages.size()==1&&scenario.equals("concurrent")) {
                        assertNotNull(s.snapshot().object(stages.get(0)));
                        try {
                            var branch=V1EnvelopeWriter.seal(ROOT,DeviceWriter.signed(ROOT,key,"remote",new byte[8],List.of()));
                            store.publish(branch.id(),branch.bytes());remote[0]=branch.id();
                            s.replace(discover(sync).snapshot());
                        }catch(Exception e){throw new AssertionError(e);}
                    }
                });
                assertEquals(2,stages.size());
                var restarted=discover(sync);
                if(scenario.equals("ambiguous")) {
                    assertEquals(PUBLICATION_INCOMPLETE,result.status());assertNull(result.objectId());
                    assertEquals(count+1,s.snapshot().objects().size());assertNull(s.snapshot().object(stages.get(1)));
                    assertEquals(count+2,restarted.snapshot().objects().size());assertNotNull(restarted.snapshot().object(stages.get(1)));
                    assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(s.snapshot(),device).state());
                    faults.fail="";
                    assertEquals(PUBLISHED,DevicePresentationUpdate.publish(ROOT,restarted,key,NAME,new byte[8],store).status());
                    assertEquals(1,discover(sync).snapshot().topology().currentDeviceHeads(device).size());
                } else {
                    assertEquals(PUBLISHED,result.status());assertEquals(stages.get(1),result.objectId());
                    for(var id:original)assertTrue(restarted.snapshot().topology().ancestor(id,result.objectId()));
                    assertEquals(remote[0]==null?Set.of(result.objectId()):Set.of(result.objectId(),remote[0]),
                            restarted.snapshot().topology().currentDeviceHeads(device));
                    if(remote[0]!=null) {
                        assertFalse(restarted.snapshot().topology().ancestor(remote[0],result.objectId()));
                        assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(restarted.snapshot(),device).state());
                    }else assertEquals(Set.of(NAME),DevicePresentation.evaluate(restarted.snapshot(),device).names());
                    // Independently decrypt, validate assertion and provenance of each retained stage.
                    for(var id:stages) {
                        var d=(AcceptedDevice)restarted.snapshot().object(id);
                        check(sync,s,new DevicePresentationUpdate.Result(PUBLISHED,id),key,NAME,Set.copyOf(d.parents()));
                    }
                    assertEquals(count+2+(remote[0]==null?0:1),restarted.snapshot().objects().size());
                }
            }
        }
    }
    static Set<String> localNames(Path local)throws IOException {
        try(var paths=Files.walk(local)) {return paths.map(local::relativize).map(Path::toString).collect(java.util.stream.Collectors.toSet());}
    }
    void child(Path sync,Path local,String mode,int expected)throws Exception {
        var paths=new ArrayList<String>();
        for(var type:List.of(FoldProcess.class,NioDiscoverySource.class,DiscoverySource.class,LinuxDurability.class))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"--enable-native-access=ALL-UNNAMED",
                "--illegal-native-access=deny","-cp",String.join(java.io.File.pathSeparator,paths),FoldProcess.class.getName(),sync.toString(),local.toString(),mode)
                .redirectErrorStream(true).start();
        try {
            assertTrue(child.waitFor(30,java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(expected,child.exitValue(),new String(child.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));
        }finally{child.destroyForcibly();}
    }
    @Test void haltAndFreshJvmContinuationNeedNoFoldRecord()throws Exception {
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        SecurityBytes device;
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            binding.create(BINDING);
            try(var key=DeviceIdentityLifecycle.createNew(binding.read(),keys)){device=new SecurityBytes(key.deviceId(),32);seed(key,store,15,false);}
        }
        var files=localNames(local);var original=discover(sync).snapshot().topology().currentDeviceHeads(device);
        child(sync,local,"halt",73);
        var partial=discover(sync);assertEquals(16,partial.snapshot().objects().size());
        assertEquals(2,partial.snapshot().topology().currentDeviceHeads(device).size());
        assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(partial.snapshot(),device).state());
        assertEquals(files,localNames(local));
        child(sync,local,"continue",0);
        var complete=discover(sync);assertEquals(17,complete.snapshot().objects().size());
        var heads=complete.snapshot().topology().currentDeviceHeads(device);assertEquals(1,heads.size());
        for(var id:original)assertTrue(complete.snapshot().topology().ancestor(id,heads.iterator().next()));
        assertEquals(Set.of(NAME),DevicePresentation.evaluate(complete.snapshot(),device).names());
        assertEquals(files,localNames(local));
    }
    public static final class FoldProcess {
        public static void main(String[] args)throws Exception {
            var sync=Path.of(args[0]);var local=Path.of(args[1]);
            try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
                var key=DeviceIdentityLifecycle.loadExisting(binding.read(),keys);var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
                var s=discover(sync);var device=new SecurityBytes(key.deviceId(),32);
                if(args[2].equals("continue")&&(s.snapshot().objects().size()!=16||s.snapshot().topology().currentDeviceHeads(device).size()!=2))
                    throw new AssertionError("Partial history not discovered");
                var result=DevicePresentationUpdate.publish(ROOT,s,key,NAME,new byte[8],store,()->{
                    if(args[2].equals("halt")&&s.snapshot().objects().size()==16)Runtime.getRuntime().halt(73);
                });
                if(!args[2].equals("continue")||result.status()!=PUBLISHED||s.snapshot().topology().currentDeviceHeads(device).size()!=1)
                    throw new AssertionError("Fresh update failed");
            }
        }
    }
}
