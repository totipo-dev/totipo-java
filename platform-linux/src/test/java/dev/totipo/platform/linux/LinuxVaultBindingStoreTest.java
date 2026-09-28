package dev.totipo.platform.linux;

import dev.totipo.format.VaultBindingStore;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LinuxVaultBindingStoreTest {
    @TempDir(factory=LocalStorageTempDirectory.class) Path directory;
    @Test void exactReopenMismatchCorruptionAndNoReplacement() throws Exception {
        byte[] anchor=new byte[32];Arrays.fill(anchor,(byte)42);
        try(var store=LinuxVaultBindingStore.open(directory)){
            assertEquals(VaultBindingStore.State.ABSENT,store.read().state());store.create(anchor);
            assertArrayEquals(anchor,store.read().bytes());
            byte[] copy=store.read().bytes();copy[0]^=1;assertArrayEquals(anchor,store.read().bytes());
        }
        try(var store=LinuxVaultBindingStore.open(directory)){
            store.create(anchor);assertArrayEquals(anchor,store.read().bytes());
            assertThrows(IOException.class,()->store.create(new byte[32]));assertArrayEquals(anchor,store.read().bytes());
            for(int size:List.of(0,31,33,4096)){
                Files.write(directory.resolve(LinuxVaultBindingStore.FILE),new byte[size]);
                assertEquals(VaultBindingStore.State.CORRUPT,store.read().state());
                assertThrows(IOException.class,()->store.create(anchor));assertEquals(size,Files.size(directory.resolve(LinuxVaultBindingStore.FILE)));
            }
        }
    }
    @Test void failedPersistenceNeverLeavesPartialFinalBinding() throws Exception {
        for(String point:List.of("before-force","after-force","before-install","after-install","after-directory-sync")){
            Path local=Files.createDirectory(directory.resolve(point));
            var ops=new LinuxVaultBindingStore.Operations(){@Override void at(String p)throws IOException{if(p.equals(point))throw new IOException("injected");}};
            try(var store=LinuxVaultBindingStore.open(local,ops)){assertThrows(IOException.class,()->store.create(new byte[32]));}
            try(var reopened=LinuxVaultBindingStore.open(local)){
                assertEquals(point.startsWith("after-install")||point.equals("after-directory-sync")?VaultBindingStore.State.PRESENT:VaultBindingStore.State.ABSENT,reopened.read().state());
                reopened.create(new byte[32]);assertArrayEquals(new byte[32],reopened.read().bytes());
            }
        }
    }
    @Test void abruptProcessDeathBeforeAndAfterAtomicInstall() throws Exception {
        String cp=String.join(java.io.File.pathSeparator,location(LinuxVaultBindingStore.class),location(VaultBindingStore.class),location(LinuxVaultBindingStoreTest.class),location(dev.totipo.storage.nio.StorageDurability.class));
        for(String point:List.of("after-force","after-install","after-directory-sync")){
            Path local=Files.createDirectory(directory.resolve(point));
            var process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),"--enable-native-access=ALL-UNNAMED","-cp",cp,Crash.class.getName(),local.toString(),point).redirectErrorStream(true).start();
            try{assertTrue(process.waitFor(20,TimeUnit.SECONDS));assertEquals(0,process.exitValue(),new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8));}
            finally{process.destroyForcibly();}
            try(var store=LinuxVaultBindingStore.open(local)){
                assertEquals(point.equals("after-force")?VaultBindingStore.State.ABSENT:VaultBindingStore.State.PRESENT,store.read().state());
                store.create(new byte[32]);assertEquals(32,Files.size(local.resolve(LinuxVaultBindingStore.FILE)));
            }
        }
    }
    static String location(Class<?> type)throws Exception{return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();}
    public static final class Crash {
        public static void main(String[] args)throws Exception{
            var ops=new LinuxVaultBindingStore.Operations(){@Override void at(String point){if(point.equals(args[1]))Runtime.getRuntime().halt(0);}};
            try(var store=LinuxVaultBindingStore.open(Path.of(args[0]),ops)){store.create(new byte[32]);}
            throw new AssertionError("Missed halt point");
        }
    }
}
