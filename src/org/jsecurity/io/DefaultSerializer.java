package org.jsecurity.io;

import java.io.*;

/**
 * Serializer implementation that uses the default JVM serialization mechanism (Object Input/Output Streams).
 *
 * @author Les Hazlewood
 * @since Apr 23, 2008 8:51:30 AM
 */
public class DefaultSerializer implements Serializer {

    public byte[] serialize(Object o) throws SerializationException {
        if (o == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BufferedOutputStream bos = new BufferedOutputStream(baos);

        try {
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(o);
            oos.close();
            return baos.toByteArray();
        } catch (IOException e) {
            String msg = "Unable to serialize object [" + o + "].";
            throw new SerializationException(msg, e);
        }
    }

    public Object deserialize(byte[] serialized) throws SerializationException {
        if (serialized == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        ByteArrayInputStream bais = new ByteArrayInputStream( serialized );
        BufferedInputStream bis = new BufferedInputStream(bais);
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object deserialized = ois.readObject();
            ois.close();
            return deserialized;
        } catch (Exception e) {
            String msg = "Unable to deserialze argument byte array.";
            throw new SerializationException(msg, e );
        }
    }
}
