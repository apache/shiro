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
package org.apache.ki.crypto.hash;

/**
 * A Cryptoraphic <tt>Hash</tt> represents a one-way conversion algorithm that transforms an input source to an underlying
 * byte array.
 *
 * @author Les Hazlewood
 * @see AbstractHash
 * @see Md2Hash
 * @see Md5Hash
 * @see Sha1Hash
 * @see Sha256Hash
 * @see Sha384Hash
 * @see Sha512Hash
 * @since 0.9
 */
public interface Hash {

    /**
     * Returns this Hash's byte array, that is, the hashed value of the original input source.
     *
     * @return this Hash's byte array, that is, the hashed value of the original input source.
     * @see #toHex
     * @see #toBase64
     */
    byte[] getBytes();

    /**
     * Returns a Hex encoding of this Hash's {@link #getBytes byte array}.
     *
     * @return a Hex encoding of this Hash's {@link #getBytes byte array}.
     */
    String toHex();

    /**
     * Returns a Base64 encoding of this Hash's {@link #getBytes byte array}.
     *
     * @return a Base64 encoding of this Hash's {@link #getBytes byte array}.
     */
    String toBase64();
}
