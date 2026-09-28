package dev.totipo.format;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultLifecycleResult.Status.*;

class VaultLifecycleTest {
    static final Argon2idKdf KDF = (p,s) -> CryptoSupport.sha256(p,s);
    static final byte[] PASSWORD = CryptoSupport.ascii("password");
    static final byte[] ROOT = VaultBootstrapWriterTest.field(32,1);
    static byte[] candidate(byte[] root) { return new VaultBootstrapWriter(KDF).encode(PASSWORD,root,new byte[16],new byte[12]); }
    static byte[] binding(byte[] root) { try(var u=VaultUnlockResult.unlocked(root)) { return u.binding(); } }
    static final class Harness {
        final MemoryBindingStore memory=new MemoryBindingStore();
        final FakeBootstrapStorage store=new FakeBootstrapStorage();
        final List<byte[]> draws=new ArrayList<>();
        int snapshots;
        final DiscoverySource source=()-> { snapshots++; return new DiscoverySource.Snapshot(List.of(),DiscoverySource.SnapshotIssue.NONE); };
        final EntropySource entropy=b->{draws.add(b);Arrays.fill(b,(byte)1);};
        VaultLifecycle lifecycle(){return new VaultLifecycle(store,memory,source,entropy,new VaultBootstrapWriter(KDF),new VaultUnlocker(KDF));}
    }
    @Test void authenticateBeforeEstablishingAndRequireExactBinding() throws Exception {
        var h=new Harness(); h.store.canonical=candidate(ROOT);
        try(var r=h.lifecycle().openConfigured(PASSWORD)){ assertEquals(OPENED_ESTABLISHED,r.status()); }
        assertArrayEquals(binding(ROOT),h.memory.bytes);
        h.store.canonical=candidate(new byte[32]);
        try(var r=h.lifecycle().openConfigured(PASSWORD)){ assertEquals(ESTABLISHED_BINDING_MISMATCH,r.status()); }
        h.memory.bytes=new byte[0];
        try(var r=h.lifecycle().openConfigured(PASSWORD)){ assertEquals(LOCAL_BINDING_CORRUPT,r.status()); }
        assertEquals(0,h.memory.bytes.length);
    }
    @Test void creationAndPostInstallFailureHaveNoPendingState() {
        for(var fault: List.of(FakeBootstrapStorage.Fault.NONE,FakeBootstrapStorage.Fault.INSTALL_AFTER_PUBLICATION)){
            var h=new Harness();h.store.fault=fault;
            try(var r=h.lifecycle().createNew(PASSWORD)){
                assertEquals(fault==FakeBootstrapStorage.Fault.NONE?CREATED_ESTABLISHED:PUBLICATION_INCOMPLETE,r.status());
            }
            h.store.fault=FakeBootstrapStorage.Fault.NONE;
            try(var r=h.lifecycle().openConfigured(PASSWORD)){assertEquals(OPENED_ESTABLISHED,r.status());}
            assertEquals(32,h.memory.bytes.length);
        }
    }
}
