package dev.totipo.platform.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class LinuxSecurityMemoryStorageTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path journal() { return dir.resolve(LinuxSecurityMemoryStorage.JOURNAL); }
    static class Faults extends LinuxSecurityMemoryStorage.Operations {
        int forces, syncs, writes, journalSyncs;
        boolean forceFail, syncFail, truncateFail, partial, journalSyncFail;
        final java.util.List<String> barriers = new java.util.ArrayList<>();
        @Override void syncJournal(Path path) throws IOException {
            journalSyncs++; barriers.add("journal");
            if(journalSyncFail) throw new IOException("injected adoption journal fsync");
            super.syncJournal(path);
        }
        @Override int write(FileChannel c, ByteBuffer b, long p) throws IOException {
            writes++;
            if (partial) {
                var slice=b.slice(); slice.limit(Math.min(5,slice.remaining()));
                int n=c.write(slice,p); b.position(b.position()+n); throw new IOException("injected write");
            }
            int limit=b.limit(); b.limit(Math.min(limit,b.position()+3));
            try { return super.write(c,b,p); } finally { b.limit(limit); }
        }
        @Override void force(FileChannel c) throws IOException {
            barriers.add("force");
            forces++; if(forceFail) throw new IOException("injected force"); super.force(c);
        }
        @Override void syncDirectory(Path p) throws IOException {
            barriers.add("directory");
            syncs++; if(syncFail) throw new IOException("injected directory"); super.syncDirectory(p);
        }
        @Override void truncate(FileChannel c,long p) throws IOException {
            if(truncateFail) throw new IOException("injected truncate"); super.truncate(c,p);
        }
    }
    static void poisoned(LinuxSecurityMemoryStorage s) {
        assertThrows(IOException.class,s::openRead);
        assertThrows(IOException.class,()->s.initializeDurably(new byte[1]));
        assertThrows(IOException.class,()->s.appendDurably(new byte[1]));
        assertThrows(IOException.class,()->s.truncateDurably(0));
    }
    @Test void absentPermissionsLocksAndLifecycle() throws Exception {
        var s=LinuxSecurityMemoryStorage.open(dir);
        assertNull(s.openRead()); assertFalse(Files.exists(journal()));
        assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(dir));
        assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(dir.resolve(".")));
        s.initializeDurably(new byte[]{1,2,3});
        for(String name:new String[]{LinuxSecurityMemoryStorage.JOURNAL,LinuxSecurityMemoryStorage.LOCK})
            assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(dir.resolve(name)));
        var reader=s.openRead(); s.close(); s.close();
        assertThrows(IOException.class,reader::read); poisoned(s);
        assertTrue(Files.exists(dir.resolve(LinuxSecurityMemoryStorage.LOCK)));
        try(var next=LinuxSecurityMemoryStorage.open(dir)) { assertNotNull(next.openRead()); }
    }
    @Test void invalidDirectoriesAndEntries() throws Exception {
        assertThrows(IllegalArgumentException.class,()->LinuxSecurityMemoryStorage.open(Path.of("relative")));
        assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(dir.resolve("missing")));
        Path unicode=Files.createDirectory(dir.resolve("日本語-😀"));
        try(var s=LinuxSecurityMemoryStorage.open(unicode)) { s.initializeDurably(new byte[]{1}); }
        Path inaccessible=Files.createDirectory(dir.resolve("inaccessible"));
        var permissions=Files.getPosixFilePermissions(inaccessible);
        Files.setPosixFilePermissions(inaccessible,PosixFilePermissions.fromString("---------"));
        try { assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(inaccessible)); }
        finally { Files.setPosixFilePermissions(inaccessible,permissions); }
        Path link=dir.resolve("link"); Files.createSymbolicLink(link,dir);
        assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(link)); Files.delete(link);
        Files.write(link,new byte[0]); assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(link));
        for(String name:new String[]{LinuxSecurityMemoryStorage.JOURNAL,LinuxSecurityMemoryStorage.LOCK}) {
            Path fixture=Files.createDirectory(dir.resolve(name+"-fixture"));
            Path p=fixture.resolve(name); Files.createSymbolicLink(p,link);
            assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(fixture));
            Path other=Files.createDirectory(dir.resolve(name+"-directory"));
            Files.createDirectory(other.resolve(name));
            assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(other));
        }
    }
    @Test void existingPermissionsArePreservedAndLockInodeIsReused() throws Exception {
        Files.write(journal(),new byte[0]);
        var mode=PosixFilePermissions.fromString("rw-r-----"); Files.setPosixFilePermissions(journal(),mode);
        Object key;
        try(var s=LinuxSecurityMemoryStorage.open(dir)) {
            assertNotNull(s.openRead());
            key=Files.readAttributes(dir.resolve(LinuxSecurityMemoryStorage.LOCK),java.nio.file.attribute.BasicFileAttributes.class).fileKey();
        }
        try(var s=LinuxSecurityMemoryStorage.open(dir)) {
            assertNotNull(s.openRead());
            assertEquals(key,Files.readAttributes(dir.resolve(LinuxSecurityMemoryStorage.LOCK),java.nio.file.attribute.BasicFileAttributes.class).fileKey());
            assertEquals(mode,Files.getPosixFilePermissions(journal()));
        }
    }
    @Test void existingBytesNeverOverwrittenAndStabilized() throws Exception {
        for(byte[] bytes:new byte[][]{new byte[0],new byte[]{9,8,7},new byte[300]}) {
            Files.write(journal(),bytes); var f=new Faults();
            try(var s=LinuxSecurityMemoryStorage.open(dir,f)) {
                assertEquals(0,f.forces); assertEquals(1,f.journalSyncs); assertEquals(1,f.syncs);
                assertEquals(java.util.List.of("journal","directory"),f.barriers);
                assertThrows(IOException.class,()->s.initializeDurably(new byte[]{4}));
                try(var r=s.openRead()) { assertNotNull(r); assertArrayEquals(bytes,r.readAllBytes()); }
            }
            assertArrayEquals(bytes,Files.readAllBytes(journal()));
        }
        for(boolean fileSync:new boolean[]{true,false}) {
            var f=new Faults(); f.journalSyncFail=fileSync; f.syncFail=!fileSync;
            byte[] before=Files.readAllBytes(journal());
            assertThrows(IOException.class,()->LinuxSecurityMemoryStorage.open(dir,f));
            assertEquals(fileSync ? java.util.List.of("journal") : java.util.List.of("journal","directory"),f.barriers);
            assertEquals(0,f.forces);
            assertArrayEquals(before,Files.readAllBytes(journal()));
            try(var s=LinuxSecurityMemoryStorage.open(dir)) { assertNotNull(s.openRead()); }
        }
    }
    @Test void fullShortWritesExactnessSnapshotsAndOffsets() throws Exception {
        var f=new Faults(); byte[] prefix=new byte[20000]; Arrays.fill(prefix,(byte)42);
        try(var s=LinuxSecurityMemoryStorage.open(dir,f)) {
            s.initializeDurably(prefix); assertEquals(1,f.syncs);
            assertEquals(java.util.List.of("force","directory"),f.barriers);
            assertEquals(0,f.journalSyncs);
            for(int chunk:new int[]{1,7,65536}) {
                try(var r=s.openRead()) {
                    assertThrows(IOException.class,s::openRead);
                    assertThrows(IOException.class,()->s.appendDurably(new byte[1]));
                    assertThrows(IOException.class,()->s.truncateDurably(1));
                    assertThrows(IOException.class,()->s.initializeDurably(new byte[1]));
                    var out=new java.io.ByteArrayOutputStream(); byte[] b=new byte[chunk]; int n;
                    while((n=r.read(b))>=0) out.write(b,0,n);
                    assertArrayEquals(prefix,out.toByteArray());
                }
            }
            s.appendDurably(new byte[]{1,2,3,4});
            assertArrayEquals(prefix,Arrays.copyOf(Files.readAllBytes(journal()),prefix.length));
            assertArrayEquals(new byte[]{1,2,3,4},Arrays.copyOfRange(Files.readAllBytes(journal()),prefix.length,prefix.length+4));
            assertEquals(1,f.syncs); assertEquals(2,f.forces);
            assertThrows(IOException.class,()->s.truncateDurably(-1));
            assertThrows(IOException.class,()->s.truncateDurably(prefix.length+5));
            s.truncateDurably(prefix.length); assertEquals(3,f.forces); assertEquals(1,f.syncs);
            try(var r=s.openRead()) {
                Files.write(journal(),new byte[]{99},StandardOpenOption.APPEND);
                assertEquals(prefix.length,r.readAllBytes().length);
            }
            assertThrows(IOException.class,()->s.appendDurably(new byte[1])); poisoned(s);
        }
    }

    @Test void initializationFailuresPreserveEvidence() throws Exception {
        for(int mode=0;mode<3;mode++) {
            Path p=Files.createDirectory(dir.resolve("mode"+mode)); var f=new Faults();
            f.forceFail=mode==0; f.syncFail=mode==1; f.partial=mode==2;
            try(var s=LinuxSecurityMemoryStorage.open(p,f)) {
                assertThrows(IOException.class,()->s.initializeDurably(new byte[12])); poisoned(s);
                assertEquals(mode==2?5:12,Files.size(p.resolve(LinuxSecurityMemoryStorage.JOURNAL)));
            }
            try(var s=LinuxSecurityMemoryStorage.open(p);var r=s.openRead()) { assertNotNull(r); }
        }
    }
    @Test void ambiguousAppendAndTruncateFailuresPoisonWithoutRollback() throws Exception {
        for(int mode=0;mode<4;mode++) {
            Path p=Files.createDirectory(dir.resolve("mode"+mode)); var f=new Faults();
            try(var s=LinuxSecurityMemoryStorage.open(p,f)) {
                s.initializeDurably(new byte[12]);
                f.partial=mode==0; f.forceFail=mode==1||mode==2; f.truncateFail=mode==3;
                if(mode<2) assertThrows(IOException.class,()->s.appendDurably(new byte[20]));
                else assertThrows(IOException.class,()->s.truncateDurably(6));
                poisoned(s);
                assertEquals(new long[]{17,32,6,12}[mode],Files.size(p.resolve(LinuxSecurityMemoryStorage.JOURNAL)));
            }
            try(var s=LinuxSecurityMemoryStorage.open(p);var r=s.openRead()) { assertNotNull(r); }
        }
    }

}
