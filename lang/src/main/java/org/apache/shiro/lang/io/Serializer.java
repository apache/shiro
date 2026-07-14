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

import java.io.ObjectInputFilter;

/**
 * A <code>Serializer</code> converts objects to raw binary data and vice versa, enabling persistent storage
 * of objects to files, HTTP cookies, or other mechanism.
 * <p/>
 * A <code>Serializer</code> should only do conversion, never change the data, such as encoding/decoding or
 * encryption.  These orthogonal concerns are handled elsewhere by Shiro, for example, via
 * {@link org.apache.shiro.lang.codec.CodecSupport CodecSupport} and {@link org.apache.shiro.crypto.CipherService CipherService}s.
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
     * @throws SerializationException if an error occurs converting the Object into a byte[] array.
     */
    byte[] serialize(T o) throws SerializationException;

    /**
     * Converts the specified raw byte[] array back into an original Object form.  This byte[] array is expected to
     * be the output of a previous {@link #serialize(Object) serialize} method call.
     *
     * @param serialized the raw data resulting from a previous {@link #serialize(Object) serialize} call.
     * @return the Object that was previously serialized into the raw byte[] array.
     * @throws SerializationException if an error occurs converting the raw byte[] array back into an Object.
     */
    T deserialize(byte[] serialized) throws SerializationException;

    /**
     * Returns the optional <a href="https://openjdk.org/jeps/290">JEP-290</a> {@link ObjectInputFilter} this
     * serializer applies while deserializing, or {@code null} if none is configured (the default).
     * <p/>
     * Serializers that do not perform Java object deserialization may ignore this; the default implementation
     * returns {@code null}.
     *
     * @return the configured {@code ObjectInputFilter}, or {@code null} if none is configured.
     * @since 3.0.1
     */
    default ObjectInputFilter getObjectInputFilter() {
        return null;
    }

    /**
     * Sets an optional <a href="https://openjdk.org/jeps/290">JEP-290</a> {@link ObjectInputFilter} to apply while
     * deserializing, providing defense-in-depth against malicious serialized payloads (for example a class or
     * resource-limit allow-list) in addition to any validation the caller performs on the deserialized result.
     * <p/>
     * Serializers that do not perform Java object deserialization may ignore this; the default implementation is a
     * no-op. {@link DefaultSerializer} applies the filter to the {@link java.io.ObjectInputStream} it uses.
     *
     * @param objectInputFilter the filter to apply, or {@code null} to disable filtering (the default).
     * @since 3.0.1
     */
    default void setObjectInputFilter(ObjectInputFilter objectInputFilter) {
    }
}
