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
package org.apache.shiro.util;

import org.apache.shiro.codec.Base64;
import org.apache.shiro.codec.CodecSupport;
import org.apache.shiro.codec.Hex;

import java.io.*;
import java.util.Arrays;

/**
 * Very simple {@link ByteSource ByteSource} implementation that maintains an internal {@code byte[]} array and uses the
 * {@link Hex Hex} and {@link Base64 Base64} codec classes to support the
 * {@link #toHex() toHex()} and {@link #toBase64() toBase64()} implementations.
 * <p/>
 * The constructors on this class accept the following implicit byte-backed data types and will convert them to
 * a byte-array automatically:
 * <ul>
 * <li>byte[]</li>
 * <li>char[]</li>
 * <li>String</li>
 * <li>{@link ByteSource ByteSource}</li>
 * <li>{@link File File}</li>
 * <li>{@link InputStream InputStream}</li>
 * </ul>
 *
 * @since 1.0
 */
public class SimpleByteSource implements ByteSource {

    private final byte[] bytes;
    private String cachedHex;
    private String cachedBase64;

    public SimpleByteSource(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Creates an instance by converting the characters to a byte array (assumes UTF-8 encoding).
     *
     * @param chars the source characters to use to create the underlying byte array.
     * @since 1.1
     */
    public SimpleByteSource(char[] chars) {
        this.bytes = CodecSupport.toBytes(chars);
    }

    /**
     * Creates an instance by converting the String to a byte array (assumes UTF-8 encoding).
     *
     * @param string the source string to convert to a byte array (assumes UTF-8 encoding).
     * @since 1.1
     */
    public SimpleByteSource(String string) {
        this.bytes = CodecSupport.toBytes(string);
    }

    /**
     * Creates an instance using the sources bytes directly - it does not create a copy of the
     * argument's byte array.
     *
     * @param source the source to use to populate the underlying byte array.
     * @since 1.1
     */
    public SimpleByteSource(ByteSource source) {
        this.bytes = source.getBytes();
    }

    /**
     * Creates an instance by converting the file to a byte array.
     *
     * @param file the file from which to acquire bytes.
     * @since 1.1
     */
    public SimpleByteSource(File file) {
        this.bytes = new BytesHelper().getBytes(file);
    }

    /**
     * Creates an instance by converting the stream to a byte array.
     *
     * @param stream the stream from which to acquire bytes.
     * @since 1.1
     */
    public SimpleByteSource(InputStream stream) {
        this.bytes = new BytesHelper().getBytes(stream);
    }

    public byte[] getBytes() {
        return this.bytes;
    }

    public String toHex() {
        if ( this.cachedHex == null ) {
            this.cachedHex = Hex.encodeToString(getBytes());
        }
        return this.cachedHex;
    }

    public String toBase64() {
        if ( this.cachedBase64 == null ) {
            this.cachedBase64 = Base64.encodeToString(getBytes());
        }
        return this.cachedBase64;
    }

    public String toString() {
        return toBase64();
    }

    public int hashCode() {
        return toString().hashCode();
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof ByteSource) {
            ByteSource bs = (ByteSource) o;
            return Arrays.equals(getBytes(), bs.getBytes());
        }
        return false;
    }

    //will probably be removed in Shiro 2.0.  See SHIRO-203:
    //https://issues.apache.org/jira/browse/SHIRO-203
    private static final class BytesHelper extends CodecSupport {
        public byte[] getBytes(File file) {
            return toBytes(file);
        }

        public byte[] getBytes(InputStream stream) {
            return toBytes(stream);
        }
    }
}
