package org.apache.shiro.util;

import java.io.Closeable;
import java.io.IOException;

/**
 * To use try-with-resources idiom, this class supports wrapping existing ByteSource
 * object or byte array. At end of try block, it gets zeroed out automatically.
 */
public class ByteSourceWrapper implements Closeable {
    private byte[] bytes;

    private ByteSourceWrapper(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * This method generically accepts byte array or ByteSource instance.
     */
    public static ByteSourceWrapper wrap(Object value) {
        if (value instanceof byte[]) {
            byte[] bytes = (byte[]) value;
            return new ByteSourceWrapper(bytes);
        } else if (value instanceof ByteSource) {
            byte[] bytes = ((ByteSource) value).getBytes();
            return new ByteSourceWrapper(bytes);
        }
        throw new IllegalArgumentException();
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void close() throws IOException {
        CollectionUtils.wipe(bytes);
    }
}
