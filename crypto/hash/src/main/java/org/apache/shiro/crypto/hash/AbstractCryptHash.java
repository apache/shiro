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
import org.apache.shiro.lang.codec.Hex;
import org.apache.shiro.lang.util.ByteSource;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * Abstract class for hashes following the posix crypt(3) format.
 *
 * <p>These implementations must contain a salt, a salt length, can format themselves to a valid String
 * suitable for the {@code /etc/shadow} file.</p>
 *
 * <p>It also defines the hex and base64 output by wrapping the output of {@link #formatToCryptString()}.</p>
 *
 * <p>Implementation notice: Implementations should provide a static {@code fromString()} method.</p>
 *
 * @since 2.0
 */
public abstract class AbstractCryptHash implements Hash, Serializable {

    protected static final Pattern DELIMITER = Pattern.compile("\\$");

    private static final long serialVersionUID = 2483214646921027859L;

    private final String algorithmName;
    private final byte[] hashedData;
    private final ByteSource salt;

    /**
     * Cached value of the {@link #toHex() toHex()} call so multiple calls won't incur repeated overhead.
     */
    private String hexEncoded;
    /**
     * Cached value of the {@link #toBase64() toBase64()} call so multiple calls won't incur repeated overhead.
     */
    private String base64Encoded;

    /**
     * Constructs an {@link AbstractCryptHash} using the algorithm name, hashed data and salt parameters.
     *
     * <p>Other required parameters must be stored by the implementation.</p>
     *
     * @param algorithmName internal algorithm name, e.g. {@code 2y} for bcrypt and {@code argon2id} for argon2.
     * @param hashedData    the hashed data as a byte array. Does not include the salt or other parameters.
     * @param salt          the salt which was used when generating the hash.
     * @throws IllegalArgumentException if the salt is not the same size as {@link #getSaltLength()}.
     */
    public AbstractCryptHash(final String algorithmName, final byte[] hashedData, final ByteSource salt) {
        this.algorithmName = algorithmName;
        this.hashedData = Arrays.copyOf(hashedData, hashedData.length);
        this.salt = requireNonNull(salt);
        checkValid();
    }

    protected final void checkValid() {
        checkValidAlgorithm();

        checkValidSalt();
    }

    /**
     * Algorithm-specific checks of the algorithm’s parameters.
     *
     * <p>While the salt length will be checked by default, other checks will be useful.
     * Examples are: Argon2 checking for the memory and parallelism parameters, bcrypt checking
     * for the cost parameters being in a valid range.</p>
     *
     * @throws IllegalArgumentException if any of the parameters are invalid.
     */
    protected abstract void checkValidAlgorithm();

    /**
     * Default check method for a valid salt. Can be overridden, because multiple salt lengths could be valid.
     * <p>
     * By default, this method checks if the number of bytes in the salt
     * are equal to the int returned by {@link #getSaltLength()}.
     *
     * @throws IllegalArgumentException if the salt length does not match the returned value of {@link #getSaltLength()}.
     */
    protected void checkValidSalt() {
        int length = salt.getBytes().length;
        if (length != getSaltLength()) {
            String message = String.format(
                    Locale.ENGLISH,
                    "Salt length is expected to be [%d] bytes, but was [%d] bytes.",
                    getSaltLength(),
                    length
            );
            throw new IllegalArgumentException(message);
        }
    }

    /**
     * Implemented by subclasses, this specifies the KDF algorithm name
     * to use when performing the hash.
     *
     * <p>When multiple algorithm names are acceptable, then this method should return the primary algorithm name.</p>
     *
     * <p>Example: Bcrypt hashed can be identified by {@code 2y} and {@code 2a}. The method will return {@code 2y}
     * for newly generated hashes by default, unless otherwise overridden.</p>
     *
     * @return the KDF algorithm name to use when performing the hash.
     */
    @Override
    public String getAlgorithmName() {
        return this.algorithmName;
    }

    /**
     * The length in number of bytes of the salt which is needed for this algorithm.
     *
     * @return the expected length of the salt (in bytes).
     */
    public abstract int getSaltLength();

    @Override
    public ByteSource getSalt() {
        return this.salt;
    }

    /**
     * Returns only the hashed data. Those are of no value on their own. If you need to serialize
     * the hash, please refer to {@link #formatToCryptString()}.
     *
     * @return A copy of the hashed data as bytes.
     * @see #formatToCryptString()
     */
    @Override
    public byte[] getBytes() {
        return Arrays.copyOf(this.hashedData, this.hashedData.length);
    }

    @Override
    public boolean isEmpty() {
        return false;
    }

    /**
     * Returns a hex-encoded string of the underlying {@link #formatToCryptString()} formatted output}.
     * <p/>
     * This implementation caches the resulting hex string so multiple calls to this method remain efficient.
     *
     * @return a hex-encoded string of the underlying {@link #formatToCryptString()} formatted output}.
     */
    @Override
    public String toHex() {
        if (this.hexEncoded == null) {
            this.hexEncoded = Hex.encodeToString(this.formatToCryptString().getBytes(StandardCharsets.UTF_8));
        }
        return this.hexEncoded;
    }

    /**
     * Returns a Base64-encoded string of the underlying {@link #formatToCryptString()} formatted output}.
     * <p/>
     * This implementation caches the resulting Base64 string so multiple calls to this method remain efficient.
     *
     * @return a Base64-encoded string of the underlying {@link #formatToCryptString()} formatted output}.
     */
    @Override
    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeToString(this.formatToCryptString().getBytes(StandardCharsets.UTF_8));
        }
        return this.base64Encoded;
    }

    /**
     * This method <strong>MUST</strong> return a single-lined string which would also be recognizable by
     * a posix {@code /etc/passwd} file.
     *
     * @return a formatted string, e.g. {@code $2y$10$7rOjsAf2U/AKKqpMpCIn6e$tuOXyQ86tp2Tn9xv6FyXl2T0QYc3.G.} for bcrypt.
     */
    public abstract String formatToCryptString();

    /**
     * Returns {@code true} if the specified object is an AbstractCryptHash and its
     * {@link #formatToCryptString()} formatted output} is identical to
     * this AbstractCryptHash's formatted output, {@code false} otherwise.
     *
     * @param other the object (AbstractCryptHash) to check for equality.
     * @return {@code true} if the specified object is a AbstractCryptHash
     * and its {@link #formatToCryptString()} formatted output} is identical to
     * this AbstractCryptHash's formatted output, {@code false} otherwise.
     */
    @Override
    public boolean equals(final Object other) {
        if (other instanceof AbstractCryptHash) {
            final AbstractCryptHash that = (AbstractCryptHash) other;
            return this.formatToCryptString().equals(that.formatToCryptString());
        }
        return false;
    }

    /**
     * Hashes the formatted crypt string.
     *
     * <p>Implementations should not override this method, as different algorithms produce different output formats
     * and require different parameters.</p>
     *
     * @return a hashcode from the {@link #formatToCryptString() formatted output}.
     */
    @Override
    public int hashCode() {
        return Objects.hash(this.formatToCryptString());
    }

    /**
     * Simple implementation that merely returns {@link #toHex() toHex()}.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    @Override
    public String toString() {
        return new StringJoiner(", ", AbstractCryptHash.class.getSimpleName() + "[", "]")
                .add("super=" + super.toString())
                .add("algorithmName='" + algorithmName + "'")
                .add("hashedData=" + Arrays.toString(hashedData))
                .add("salt=" + salt)
                .add("hexEncoded='" + hexEncoded + "'")
                .add("base64Encoded='" + base64Encoded + "'")
                .toString();
    }
}
