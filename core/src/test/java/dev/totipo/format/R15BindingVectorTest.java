package dev.totipo.format;

import dev.totipo.conformance.VectorCaseLoader;
import java.io.IOException;
import java.util.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import static org.junit.jupiter.api.Assertions.*;

class R15BindingVectorTest {
    @TestFactory List<DynamicTest> bindingTrials()throws Exception{
        var tests=new ArrayList<DynamicTest>();
        for(var c:VectorCaseLoader.bootstrapCases()){
            if(!c.data().field("operation").string().equals("local"))continue;
            for(var trial:c.data().field("local").field("trials").array())tests.add(DynamicTest.dynamicTest(c.context()+" "+trial.field("existing").string()+" "+trial.field("expected").string(),()->{
                var memory=new MemoryBindingStore();
                memory.bytes=switch(trial.field("existing").string()){
                    case "absent"->null;case "corrupt"->new byte[0];case "different"->new byte[32];case "exact"->VaultLifecycleTest.binding(VaultLifecycleTest.ROOT);default->throw new AssertionError();};
                var store=new VaultBindingStore(){public Binding read(){return memory.read();}
                    public void create(byte[] bytes)throws IOException{if(!trial.field("acknowledged").bool())throw new IOException("unacknowledged");memory.create(bytes);}
                    public void close(){} };
                var vault=new FakeBootstrapStorage();vault.canonical=VaultLifecycleTest.candidate(VaultLifecycleTest.ROOT);
                var life=new VaultLifecycle(vault,store,()->new DiscoverySource.Snapshot(List.of(),DiscoverySource.SnapshotIssue.NONE),b->{throw new AssertionError();},new VaultBootstrapWriter(VaultLifecycleTest.KDF),new VaultUnlocker(VaultLifecycleTest.KDF));
                try(var r=life.openConfigured(trial.field("authenticated").bool()?VaultLifecycleTest.PASSWORD:new byte[0])){
                    String outcome=switch(r.status()){
                        case OPENED_ESTABLISHED->"ESTABLISHED";case LOCAL_PERSISTENCE_FAILURE->"INCOMPLETE";
                        case LOCAL_BINDING_CORRUPT->"ANCHOR_FAILURE";case AUTHENTICATION_FAILED,ESTABLISHED_BINDING_MISMATCH->"REJECTED";default->throw new AssertionError(r.status());};
                    assertEquals(trial.field("expected").string(),outcome);
                }
            }));
        }return tests;
    }
}
