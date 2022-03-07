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

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

/**
 * Serializer implementation that uses the JavaBeans
 * {@link java.beans.XMLEncoder XMLEncoder} and {@link java.beans.XMLDecoder XMLDecoder} to serialize
 * and deserialize, respectively.
 * <p/>
 * <b>NOTE:</b> The JavaBeans XMLEncoder/XMLDecoder only successfully encode/decode objects when they are
 * JavaBeans compatible!
 *
 * @since 0.9
 * @deprecated This class should not be used directly because of unsecure XMLEncoder/XMLDecoder usage.
 */
public class XmlSerializer implements Serializer {

    /**
     * Serializes the specified <code>source</code> into a byte[] array by using the
     * {@link java.beans.XMLEncoder XMLEncoder} to encode the object out to a
     * {@link java.io.ByteArrayOutputStream ByteArrayOutputStream}, where the resulting byte[] array is returned.
     * @param source the Object to convert into a byte[] array.
     * @return the byte[] array representation of the XML encoded output.
     */
    public byte[] serialize(Object source) {
        if (source == null) {
            String msg = "argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(new BufferedOutputStream(bos));
        encoder.writeObject(source);
        encoder.close();

        return bos.toByteArray();
    }

    /**
     * Deserializes the specified <code>serialized</code> source back into an Object by using a
     * {@link java.io.ByteArrayInputStream ByteArrayInputStream} to wrap the argument and then decode this
     * stream via an {@link java.beans.XMLDecoder XMLDecoder}, where the
     * {@link java.beans.XMLDecoder#readObject() readObject} call results in the original Object to return.
     * @param serialized the byte[] array representation of the XML encoded output.
     * @return the original source Object in reconstituted form.
     */
    public Object deserialize(byte[] serialized) {
        if (serialized == null) {
            throw new IllegalArgumentException("Argument cannot be null.");
        }
        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        XMLDecoder decoder = new XMLDecoder(new BufferedInputStream(bis));
        Object o = decoder.readObject();
        decoder.close();
        return o;
    }
}
