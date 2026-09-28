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
import static dev.totipo.format.InitialTokenPublication.Status.*;

class LinuxTokenFoldTest {
    @TempDir(factory=LocalStorageTempDirectory.class) Path directory;
    static final byte[] ROOT=new byte[32];
    static final SecurityBytes TOKEN=new SecurityBytes(new byte[32],32);
    static TokenValue value(String name){return new TokenValue(1,name.repeat(256),"a".repeat(256),
            new TokenValue.Credential(1,6,30,new SecurityBytes(new byte[128],128)));}
    static SnapshotSession discover(Path sync, byte[] binding){var s=new SnapshotSession(new SecurityBytes(binding,32));s.replace(DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT).snapshot());return s;}
    static TokenUpdatePublication.Context context(SnapshotSession s){return new TokenUpdatePublication.Context(new InitialDeviceAdvertisement.Context(s));}
    static InitialTokenPublication.Result fold(SnapshotSession s,DeviceIdentityResult key,V1ObjectPublicationStore store,boolean conflict){
        var desired=value("z");var intent=TokenUpdatePublication.Intent.ORDINARY;
        if(conflict){var c=TokenResolutionConfirmation.prepare(ROOT,context(s),key,TOKEN,desired,intent);
            return TokenUpdatePublication.publishConfirmed(ROOT,()->context(s),key,TOKEN,desired,new byte[8],intent,c.confirmation(),store,List.of());}
        return TokenUpdatePublication.publish(ROOT,()->context(s),key,TOKEN,desired,new byte[8],intent,store,List.of());
    }
    static void seed(SnapshotSession s,DeviceIdentityResult key,V1ObjectPublicationStore store,boolean conflict){
        for(int i=0;i<10;i++)assertNotNull(InitialTokenPublication.publishValue(ROOT,s,key,TOKEN,value(conflict&&i%2==0?"b":"a"),new byte[8],List.of(),store,List.of(),()->true).receipt());
    }
    @ParameterizedTest @ValueSource(strings={"equal","conflict","ambiguous","concurrent"})
    void realStoreRestartAndConcurrency(String scenario)throws Exception{
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        byte[] anchor=CryptoSupport.hmac(ROOT,CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())){
            binding.create(anchor);
            try(var key=DeviceIdentityLifecycle.createNew(binding.read(),keys)){
                var s=discover(sync,anchor);boolean conflict=scenario.equals("conflict");seed(s,key,store,conflict);
                var original=s.snapshot().topology().currentTokenHeads(TOKEN);assertEquals(10,original.size());
                if(conflict)assertEquals(CONFIRMATION_REQUIRED_CONFLICT,fold(s,key,store,false).status());
                var calls=new int[1];var external=new ObjectId[1];
                V1ObjectPublicationStore hooked=new V1ObjectPublicationStore(){
                    public PublicationResult publish(ObjectId id,byte[] bytes)throws IOException{
                        calls[0]++;assertNull(s.snapshot().object(id));var result=store.publish(id,bytes);
                        if(calls[0]==2&&scenario.equals("ambiguous"))throw new IOException("After install");
                        if(calls[0]==1&&scenario.equals("concurrent")){
                            var remote=new SnapshotSession(s.binding());
                            var r=InitialTokenPublication.publishValue(ROOT,remote,key,TOKEN,value("r"),new byte[8],List.of(),store,List.of(),()->true);
                            external[0]=r.receipt().objectId();s.accept(remote.snapshot().object(external[0]));
                        }
                        return result;
                    }
                    public void close(){}
                };
                var result=fold(s,key,hooked,conflict);
                assertEquals(scenario.equals("ambiguous")?PUBLICATION_INCOMPLETE:PUBLISHED_DEVICE_REQUIRED,result.status());
                assertEquals(scenario.equals("ambiguous")?2:3,calls[0]);
                var restarted=discover(sync,anchor);assertEquals(scenario.equals("ambiguous")?12:scenario.equals("concurrent")?14:13,restarted.snapshot().objects().size());
                if(scenario.equals("ambiguous")){
                    assertEquals(11,s.snapshot().objects().size());
                    assertEquals(CONFIRMATION_REQUIRED_CONFLICT,fold(restarted,key,store,false).status());
                    assertNotNull(fold(restarted,key,store,true).receipt());
                }else{
                    var last=result.receipt().objectId();for(var head:original)assertTrue(restarted.snapshot().topology().ancestor(head,last));
                    assertEquals(scenario.equals("concurrent")?2:1,restarted.snapshot().topology().currentTokenHeads(TOKEN).size());
                    if(external[0]!=null)assertFalse(restarted.snapshot().topology().ancestor(external[0],last));
                }
            }
        }
    }
    @Test void processHaltAfterAcknowledgedFirstStage()throws Exception{
        Path sync=Files.createDirectory(directory.resolve("sync")),local=Files.createDirectory(directory.resolve("local"));
        byte[] anchor=CryptoSupport.hmac(ROOT,CryptoSupport.ascii("totipo/v1/local-vault-binding"));
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())){
            binding.create(anchor);
            try(var key=DeviceIdentityLifecycle.createNew(binding.read(),keys)){seed(discover(sync,anchor),key,store,false);}
        }
        var paths=new ArrayList<String>();
        for(var type:List.of(CrashFold.class,NioDiscoverySource.class,DiscoverySource.class,LinuxDurability.class))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        var child=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"--enable-native-access=ALL-UNNAMED",
                "--illegal-native-access=deny","-cp",String.join(java.io.File.pathSeparator,paths),CrashFold.class.getName(),sync.toString(),local.toString()).redirectErrorStream(true).start();
        try{assertTrue(child.waitFor(30,java.util.concurrent.TimeUnit.SECONDS));assertEquals(73,child.exitValue(),new String(child.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));}
        finally{child.destroyForcibly();}
        var restarted=discover(sync,anchor);assertEquals(11,restarted.snapshot().objects().size());assertEquals(7,restarted.snapshot().topology().currentTokenHeads(TOKEN).size());
        try(var binding=LinuxVaultBindingStore.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var key=DeviceIdentityLifecycle.loadExisting(binding.read(),keys);var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())){
            assertEquals(CONFIRMATION_REQUIRED_CONFLICT,fold(restarted,key,store,false).status());
            assertNotNull(fold(restarted,key,store,true).receipt());assertEquals(1,discover(sync,anchor).snapshot().topology().currentTokenHeads(TOKEN).size());
        }
    }
    public static final class CrashFold {
        public static void main(String[] args)throws Exception{
            var sync=Path.of(args[0]);
            try(var binding=LinuxVaultBindingStore.open(Path.of(args[1]));var keys=LinuxDeviceProvenanceKeyStore.open(Path.of(args[1]));
                var key=DeviceIdentityLifecycle.loadExisting(binding.read(),keys);var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())){
                var s=discover(sync,binding.read().bytes());
                V1ObjectPublicationStore hooked=new V1ObjectPublicationStore(){int calls;
                    public PublicationResult publish(ObjectId id,byte[] bytes)throws IOException{
                        if(++calls==2){if(s.snapshot().objects().size()!=11)throw new AssertionError("Acknowledgement ordering");Runtime.getRuntime().halt(73);}
                        return store.publish(id,bytes);
                    }
                    public void close(){}
                };
                fold(s,key,hooked,false);throw new AssertionError("No halt");
            }
        }
    }
}
