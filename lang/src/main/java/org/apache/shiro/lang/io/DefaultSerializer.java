/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.lang.io;

import java.io.*;

/**
 * Serializer implementation that uses the default JVM serialization mechanism (Object Input/Output Streams).
 *
 * @since 0.9
 */
public class DefaultSerializer<T> implements Serializer<T> {

    /**
     * This implementation serializes the Object by using an {@link ObjectOutputStream} backed by a
     * {@link ByteArrayOutputStream}.  The {@code ByteArrayOutputStream}'s backing byte array is returned.
     *
     * @param o the Object to convert into a byte[] array.
     * @return the bytes representing the serialized object using standard JVM serialization.
     * @throws SerializationException wrapping a {@link IOException} if something goes wrong with the streams.
     */
    public byte[] serialize(T o) throws SerializationException {
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
            baos.flush();
            return baos.toByteArray();
        } catch (IOException e) {
            String msg = "Unable to serialize object [" + o + "].  " +
                    "In order for the DefaultSerializer to serialize this object, the [" + o.getClass().getName() + "] " +
                    "class must implement java.io.Serializable.";
            throw new SerializationException(msg, e);
        }
    }

    /**
     * This implementation deserializes the byte array using a {@link ObjectInputStream} using a source
     * {@link ByteArrayInputStream} constructed with the argument byte array.
     *
     * @param serialized the raw data resulting from a previous {@link #serialize(Object) serialize} call.
     * @return the deserialized/reconstituted object based on the given byte array
     * @throws SerializationException if anything goes wrong using the streams.
     */
    public T deserialize(byte[] serialized) throws SerializationException {
        if (serialized == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        ByteArrayInputStream bais = new ByteArrayInputStream(serialized);
        BufferedInputStream bis = new BufferedInputStream(bais);
        try {
            ObjectInputStream ois = new ClassResolvingObjectInputStream(bis);
            @SuppressWarnings({"unchecked"})
            T deserialized = (T) ois.readObject();
            ois.close();
            return deserialized;
        } catch (Exception e) {
            String msg = "Unable to deserialize argument byte array.";
            throw new SerializationException(msg, e);
        }
    }
}
