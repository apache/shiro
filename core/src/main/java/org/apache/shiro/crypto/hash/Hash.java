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
package org.apache.shiro.crypto.hash;

import org.apache.shiro.util.ByteSource;

/**
 * A Cryptographic {@code Hash} represents a one-way conversion algorithm that transforms an input source to an
 * underlying byte array.  Hex and Base64-encoding output of the hashed bytes are automatically supported by the
 * inherited {@link #toHex() toHex()} and {@link #toBase64() toBase64()} methods.
 * <p/>
 * The bytes returned by the parent interface's {@link #getBytes() getBytes()} are the hashed value of the
 * original input source.
 *
 * @see AbstractHash
 * @see Md2Hash
 * @see Md5Hash
 * @see Sha1Hash
 * @see Sha256Hash
 * @see Sha384Hash
 * @see Sha512Hash
 * @since 0.9
 */
public interface Hash extends ByteSource {

    /**
     * Returns the name of the algorithm used to hash the input source, for example, {@code SHA-256}, {@code MD5}, etc.
     * <p/>
     * The name is expected to be a {@link java.security.MessageDigest MessageDigest} algorithm name.
     *
     * @return the the name of the algorithm used to hash the input source, for example, {@code SHA-256}, {@code MD5}, etc.
     * @since 1.1
     */
    String getAlgorithmName();
}
