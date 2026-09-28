package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class V1ObjectPublicationStoreTest {
    @Test void snapshotOwnershipNoReplaceAndClose() throws Exception {
        var store = new FakeV1ObjectPublicationStore();
        var id = new ObjectId(new byte[32]); byte[] bytes = new byte[1024]; bytes[0] = 7;
        byte[] original = bytes.clone();
        store.afterSnapshot = () -> Arrays.fill(bytes, (byte) 1);
        assertEquals(V1ObjectPublicationStore.PublicationResult.PUBLISHED_NEW, store.publishDurably(id, bytes));
        assertArrayEquals(original, store.get(id));
        store.get(id)[0] = 0;
        store.afterSnapshot = () -> {};
        assertEquals(V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT, store.publishDurably(id, original));
        assertThrows(IOException.class, () -> store.publishDurably(id, bytes));
        assertArrayEquals(original, store.get(id));
        store.close(); store.close();
        assertThrows(IOException.class, () -> store.publishDurably(id, original));
        assertArrayEquals(original, store.get(id));
    }
    @Test void wrongLengthNullUnsafeAndWrongSizedExistingTargetsFail() throws Exception {
        var store = new FakeV1ObjectPublicationStore(); var id = new ObjectId(new byte[32]);
        for (int length : new int[]{0, 1023, 1025}) {
            assertThrows(IllegalArgumentException.class, () -> store.publishDurably(id, new byte[length]));
        }
        assertThrows(NullPointerException.class, () -> store.publishDurably(null, new byte[1024]));
        assertThrows(NullPointerException.class, () -> store.publishDurably(id, null));
        assertEquals(0, store.calls);
        store.seed(id, new byte[1023]);
        assertThrows(IOException.class, () -> store.publishDurably(id, new byte[1024]));
        assertEquals(1023, store.get(id).length);
        store.fault = FakeV1ObjectPublicationStore.Fault.UNSAFE;
        assertThrows(IOException.class, () -> store.publishDurably(id, new byte[1024]));
    }
}
