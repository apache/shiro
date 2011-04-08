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

import java.io.File;
import java.io.InputStream;

/**
 * A {@code ByteSource} wraps a byte array and provides additional encoding operations.  Most users will find the
 * {@link Util} inner class sufficient to construct ByteSource instances.
 *
 * @since 1.0
 */
public interface ByteSource {

    /**
     * Returns the wrapped byte array.
     *
     * @return the wrapped byte array.
     */
    public byte[] getBytes();

    /**
     * Returns the <a href="http://en.wikipedia.org/wiki/Hexadecimal">Hex</a>-formatted String representation of the
     * underlying wrapped byte array.
     *
     * @return the <a href="http://en.wikipedia.org/wiki/Hexadecimal">Hex</a>-formatted String representation of the
     *         underlying wrapped byte array.
     */
    public String toHex();

    /**
     * Returns the <a href="http://en.wikipedia.org/wiki/Base64">Base 64</a>-formatted String representation of the
     * underlying wrapped byte array.
     *
     * @return the <a href="http://en.wikipedia.org/wiki/Base64">Base 64</a>-formatted String representation of the
     *         underlying wrapped byte array.
     */
    public String toBase64();

    /**
     * Utility class that can construct ByteSource instances.  This is slightly nicer than needing to know the
     * {@code ByteSource} implementation class to use.
     *
     * @since 1.2
     */
    public static final class Util {

        /**
         * Returns a new {@code ByteSource} instance representing the specified byte array.
         *
         * @param bytes the bytes to represent as a {@code ByteSource} instance.
         * @return a new {@code ByteSource} instance representing the specified byte array.
         */
        public static ByteSource bytes(byte[] bytes) {
            return new SimpleByteSource(bytes);
        }

        /**
         * Returns a new {@code ByteSource} instance representing the specified character array's bytes.  The byte
         * array is obtained assuming {@code UTF-8} encoding.
         *
         * @param chars the character array to represent as a {@code ByteSource} instance.
         * @return a new {@code ByteSource} instance representing the specified character array's bytes.
         */
        public static ByteSource bytes(char[] chars) {
            return new SimpleByteSource(chars);
        }

        /**
         * Returns a new {@code ByteSource} instance representing the specified string's bytes.  The byte
         * array is obtained assuming {@code UTF-8} encoding.
         *
         * @param string the string to represent as a {@code ByteSource} instance.
         * @return a new {@code ByteSource} instance representing the specified string's bytes.
         */
        public static ByteSource bytes(String string) {
            return new SimpleByteSource(string);
        }

        /**
         * Returns a new {@code ByteSource} instance representing the specified ByteSource.
         *
         * @param source the ByteSource to represent as a new {@code ByteSource} instance.
         * @return a new {@code ByteSource} instance representing the specified ByteSource.
         */
        public static ByteSource bytes(ByteSource source) {
            return new SimpleByteSource(source);
        }

        /**
         * Returns a new {@code ByteSource} instance representing the specified File's bytes.
         *
         * @param file the file to represent as a {@code ByteSource} instance.
         * @return a new {@code ByteSource} instance representing the specified File's bytes.
         */
        public static ByteSource bytes(File file) {
            return new SimpleByteSource(file);
        }

        /**
         * Returns a new {@code ByteSource} instance representing the specified InputStream's bytes.
         *
         * @param stream the InputStream to represent as a {@code ByteSource} instance.
         * @return a new {@code ByteSource} instance representing the specified InputStream's bytes.
         */
        public static ByteSource bytes(InputStream stream) {
            return new SimpleByteSource(stream);
        }
    }
}
