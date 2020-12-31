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

import org.apache.shiro.lang.codec.Base64;
import org.apache.shiro.lang.codec.CodecSupport;
import org.apache.shiro.lang.codec.Hex;

import java.io.Serializable;
import java.security.MessageDigest;
import java.util.Arrays;

public abstract class AbstractCryptHash extends CodecSupport implements Hash, Serializable {

    private static final long serialVersionUID = 2483214646921027859L;
    /**
     * Cached value of the {@link #toHex() toHex()} call so multiple calls won't incur repeated overhead.
     */
    private String hexEncoded;
    /**
     * Cached value of the {@link #toBase64() toBase64()} call so multiple calls won't incur repeated overhead.
     */
    private String base64Encoded;

    /**
     * Implemented by subclasses, this specifies the {@link MessageDigest MessageDigest} algorithm name
     * to use when performing the hash.
     *
     * @return the {@link MessageDigest MessageDigest} algorithm name to use when performing the hash.
     */
    @Override
    public abstract String getAlgorithmName();

    public abstract int getSaltLength();


    /**
     * Returns a hex-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting hex string so multiple calls to this method remain efficient.
     *
     * @return a hex-encoded string of the underlying {@link #getBytes byte array}.
     */
    @Override
    public String toHex() {
        if (this.hexEncoded == null) {
            this.hexEncoded = Hex.encodeToString(this.getBytes());
        }
        return this.hexEncoded;
    }

    /**
     * Returns a Base64-encoded string of the underlying {@link #getBytes byte array}.
     * <p/>
     * This implementation caches the resulting Base64 string so multiple calls to this method remain efficient.
     *
     * @return a Base64-encoded string of the underlying {@link #getBytes byte array}.
     */
    @Override
    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeToString(this.getBytes());
        }
        return this.base64Encoded;
    }

    /**
     * Simple implementation that merely returns {@link #toHex() toHex()}.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    @Override
    public String toString() {
        return this.toHex();
    }

    /**
     * Returns {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, {@code false} otherwise.
     *
     * @param other the object (Hash) to check for equality.
     * @return {@code true} if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, {@code false} otherwise.
     */
    @Override
    public boolean equals(final Object other) {
        if (other instanceof Hash) {
            final Hash that = (Hash) other;
            return MessageDigest.isEqual(this.getBytes(), that.getBytes());
        }
        return false;
    }

    /**
     * Simply returns toHex().hashCode();
     *
     * @return toHex().hashCode()
     */
    @Override
    public int hashCode() {
        if (this.getBytes() == null || this.getBytes().length == 0) {
            return 0;
        }
        return Arrays.hashCode(this.getBytes());
    }
}
