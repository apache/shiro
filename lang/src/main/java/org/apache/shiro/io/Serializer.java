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
package org.apache.shiro.io;

/**
 * A <code>Serializer</code> converts objects to raw binary data and vice versa, enabling persistent storage
 * of objects to files, HTTP cookies, or other mechanism.
 * <p/>
 * A <code>Serializer</code> should only do conversion, never change the data, such as encoding/decoding or
 * encryption.  These orthogonal concerns are handled elsewhere by Shiro, for example, via
 * {@link org.apache.shiro.codec.CodecSupport CodecSupport} and {@link org.apache.shiro.crypto.CipherService CipherService}s.
 *
 * @param <T> The type of the object being serialized and deserialized.
 * @since 0.9
 */
public interface Serializer<T> {

    /**
     * Converts the specified Object into a byte[] array.  This byte[] array must be able to be reconstructed
     * back into the original Object form via the {@link #deserialize(byte[]) deserialize} method.
     *
     * @param o the Object to convert into a byte[] array.
     * @return a byte[] array representing the Object's state that can be restored later.
     * @throws SerializationException if an error occurrs converting the Object into a byte[] array.
     */
    byte[] serialize(T o) throws SerializationException;

    /**
     * Converts the specified raw byte[] array back into an original Object form.  This byte[] array is expected to
     * be the output of a previous {@link #serialize(Object) serialize} method call.
     *
     * @param serialized the raw data resulting from a previous {@link #serialize(Object) serialize} call.
     * @return the Object that was previously serialized into the raw byte[] array.
     * @throws SerializationException if an error occurrs converting the raw byte[] array back into an Object.
     */
    T deserialize(byte[] serialized) throws SerializationException;
}
