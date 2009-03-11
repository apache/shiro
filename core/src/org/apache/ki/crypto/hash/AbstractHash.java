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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.apache.ki.codec.Base64;
import org.apache.ki.codec.CodecException;
import org.apache.ki.codec.CodecSupport;
import org.apache.ki.codec.Hex;

/**
 * Provides a base for all JSecurity Hash algorithms with support for salts and multiple hash iterations.
 *
 * <p>Read <a href="http://www.owasp.org/index.php/Hashing_Java" target="blank">http://www.owasp.org/index.php/Hashing_Java</a> for a
 * good article on the benefits of hashing, including what a 'salt' is as well as why it and multiple hash iterations
 * can be useful.
 *
 * <p>This class and its subclasses support hashing with additional capabilities of salting and multiple iterations via
 * overloaded constructors</p>.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AbstractHash extends CodecSupport implements Hash {

    /** The hashed data */
    private byte[] bytes = null;

    /** Cached value of the {@link #toHex() toHex()} call so multiple calls won't incur repeated overhead. */
    private String hexEncoded = null;
    /** Cached value of the {@link #toBase64() toBase64()} call so multiple calls won't incur repeated overhead. */
    private String base64Encoded = null;

    /**
     * Creates an new instance without any of its properties set (no hashing is performed).
     *
     * <p>Because all constructors in this class
     * (except this one) hash the <tt>source</tt> constructor argument, this default, no-arg constructor is useful in
     * scenarios whenyou have a byte array that you know is already hashed and just want to set the bytes in their
     * raw form directly on an instance.  After instantiating the instance with this default, no-arg constructor, you
     * can then immediately call {@link #setBytes setBytes} to have a fully-initiallized instance.
     */
    public AbstractHash() {
    }

    /**
     * Creates a hash of the specified <tt>source</tt> with no <tt>salt</tt> using a single hash iteration.
     *
     * <p>It is a convenience constructor that merely executes <code>this( source, null, 1);</code>.
     *
     * <p>Please see the
     * {@link #AbstractHash(Object source, Object salt, int numIterations) AbstractHash(Object,Object,int)}
     * constructor for the types of Objects that may be passed into this constructor, as well as how to support further
     * types.
     *
     * @param source the object to be hashed.
     * @throws CodecException if the specified <tt>source</tt> cannot be converted into a byte array (byte[]).
     */
    public AbstractHash(Object source) throws CodecException {
        this(source, null, 1);
    }

    /**
     * Creates a hash of the specified <tt>source</tt> using the given <tt>salt</tt> using a single hash iteration.
     *
     * <p>It is a convenience constructor that merely executes <code>this( source, salt, 1);</code>.
     *
     * <p>Please see the
     * {@link #AbstractHash(Object source, Object salt, int numIterations) AbstractHash(Object,Object,int)}
     * constructor for the types of Objects that may be passed into this constructor, as well as how to support further
     * types.
     *
     * @param source the source object to be hashed.
     * @param salt   the salt to use for the hash
     * @throws CodecException if either constructor argument cannot be converted into a byte array.
     */
    public AbstractHash(Object source, Object salt) throws CodecException {
        this(source, salt, 1);
    }

    /**
     * Creates a hash of the specified <tt>source</tt> using the given <tt>salt</tt> a total of
     * <tt>hashIterations</tt> times.
     *
     * <p>By default, this class only supports Object method arguments of
     * type <tt>byte[]</tt>, <tt>char[]</tt> and <tt>String</tt>.  If either argument is anything other than these
     * types a {@link org.apache.ki.codec.CodecException CodecException} will be thrown.
     *
     * <p>If you want to be able to hash other object types, or use other salt types, you need to override the
     * {@link #toBytes(Object) toBytes(Object)} method to support those specific types.  Your other option is to
     * convert your arguments to one of the default three supported types first before passing them in to this
     * constructor</tt>.
     *
     * @param source         the source object to be hashed.
     * @param salt           the salt to use for the hash
     * @param hashIterations the number of times the <tt>source</tt> argument hashed for attack resiliency.
     * @throws CodecException if either Object constructor argument cannot be converted into a byte array.
     */
    public AbstractHash(Object source, Object salt, int hashIterations) throws CodecException {
        byte[] sourceBytes = toBytes(source);
        byte[] saltBytes = null;
        if (salt != null) {
            saltBytes = toBytes(salt);
        }
        byte[] hashedBytes = hash(sourceBytes, saltBytes, hashIterations);
        setBytes(hashedBytes);
    }

    /**
     * Implemented by subclasses, this specifies the name of the {@link MessageDigest MessageDigest} algorithm
     * to use when performing the hash.
     *
     * @return the {@link MessageDigest MessageDigest} algorithm to use when performing the hash.
     */
    protected abstract String getAlgorithmName();

    public byte[] getBytes() {
        return this.bytes;
    }

    /**
     * Sets the raw bytes stored by this hash instance.
     *
     * <p>The bytes are kept in raw form - they will not be hashed/changed.  This is primarily a utility method for
     * constructing a Hash instance when the hashed value is already known.
     *
     * @param alreadyHashedBytes the raw already-hashed bytes to store in this instance.
     */
    public void setBytes(byte[] alreadyHashedBytes) {
        this.bytes = alreadyHashedBytes;
        this.hexEncoded = null;
        this.base64Encoded = null;
    }

    /**
     * Returns the JDK MessageDigest instance to use for executing the hash.
     *
     * @param algorithmName the algorithm to use for the hash, provided by subclasses.
     * @return the MessageDigest object for the specfied <tt>algorithm</tt>.
     */
    protected MessageDigest getDigest(String algorithmName) {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new IllegalStateException(msg, e);
        }
    }

    /**
     * Hashes the specified byte array without a salt for a single iteration.
     *
     * @param bytes the bytes to hash.
     * @return the hashed bytes.
     */
    protected byte[] hash(byte[] bytes) {
        return hash(bytes, null, 1);
    }

    /**
     * Hashes the specified byte array using the given <tt>salt</tt> for a single iteration.
     *
     * @param bytes the bytes to hash
     * @param salt  the salt to use for the initial hash
     * @return the hashed bytes
     */
    protected byte[] hash(byte[] bytes, byte[] salt) {
        return hash(bytes, salt, 1);
    }

    /**
     * Hashes the specified byte array using the given <tt>salt</tt> for the specified number of iterations.
     *
     * @param bytes          the bytes to hash
     * @param salt           the salt to use for the initial hash
     * @param hashIterations the number of times the the <tt>bytes</tt> will be hashed (for attack resiliency).
     * @return the hashed bytes.
     */
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) {
        MessageDigest md = getDigest(getAlgorithmName());
        if (salt != null) {
            md.reset();
            md.update(salt);
        }
        byte[] hashed = md.digest(bytes);
        int iterations = hashIterations - 1; //already hashed once above
        //iterate remaining number:
        for (int i = 0; i < iterations; i++) {
            md.reset();
            hashed = md.digest(hashed);
        }
        return hashed;
    }

    /**
     * Returns a hex-encoded string of the underlying {@link #getBytes byte array}.
     *
     * <p>This implementation caches the resulting hex string so multiple calls to this method remain performant.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time this method is called.
     *
     * @return a hex-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toHex() {
        if (this.hexEncoded == null) {
            this.hexEncoded = Hex.encodeToString(getBytes());
        }
        return this.hexEncoded;
    }

    /**
     * Returns a Base64-encoded string of the underlying {@link #getBytes byte array}.
     *
     * <p>This implementation caches the resulting Base64 string so multiple calls to this method remain performant.
     * However, calling {@link #setBytes setBytes} will null the cached value, forcing it to be recalculated the
     * next time this method is called.
     *
     * @return a Base64-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeToString(getBytes());
        }
        return this.base64Encoded;
    }

    /**
     * Simple implementation that merely returns {@link #toHex() toHex()}.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    public String toString() {
        return toHex();
    }

    /**
     * Returns <tt>true</tt> if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, <tt>false</tt> otherwise.
     *
     * @param o the object (Hash) to check for equality.
     * @return <tt>true</tt> if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     *         this Hash's byte array, <tt>false</tt> otherwise.
     */
    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }

    /**
     * Simply returns toHex().hashCode();
     *
     * @return toHex().hashCode()
     */
    public int hashCode() {
        return toHex().hashCode();
    }
}
