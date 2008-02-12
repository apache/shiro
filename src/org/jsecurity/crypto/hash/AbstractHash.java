/*
 * Copyright (C) 2005-2008 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.crypto.hash;

import org.jsecurity.codec.Base64;
import org.jsecurity.codec.CodecException;
import org.jsecurity.codec.CodecSupport;
import org.jsecurity.codec.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Provides a base for all JSecurity Hash algorithms with support for salts and multiple hash iterations.
 *
 * <p>Read <a href="http://www.owasp.org/index.php/Hashing_Java" target="blank">http://www.owasp.org/index.php/Hashing_Java</a> for a
 * good article on the benefits of hashing, including what a 'salt' is as well as why it and multiple hash iterations
 * can be useful.
 * 
 * <p>This class and its subclasses support hashing with additional capabilities of salting and multiple iterations via
 * overloaded constructors</tt>.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class AbstractHash extends CodecSupport implements Hash {

    private byte[] bytes = null;

    //cache string ops to ensure multiple calls won't incur repeated overhead:
    private String hexEncoded = null;
    private String base64Encoded = null;

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
        this( source, null, 1 );
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
     * @param salt the salt to use for the hash
     * @throws CodecException if either constructor argument cannot be converted into a byte array.
     * @see <a href="http://www.owasp.org/index.php/Hashing_Java" target="blank">Hashing_Java</a>
     * for the benefits of salts and hash iterations.
     */
    public AbstractHash(Object source, Object salt ) throws CodecException {
        this( source, salt, 1 );
    }

    /**
     * Creates a hash of the specified <tt>source</tt> using the given <tt>salt</tt> then re-hashes the result
     * <tt>hashInterations</tt> times.
     *
     * <p>By default, this class only supports Object method arguments of
     * type <tt>byte[]</tt>, <tt>char[]</tt> and <tt>String</tt>.  If either argument is anything other than these
     * types a {@link org.jsecurity.codec.CodecException CodecException} will be thrown.
     *
     * <p>If you want to be able to hash other object types, or use other salt types, you need to override the
     * {@link #toBytes(Object) toBytes(Object)} method to support those specific types.  Your other option is to
     * convert your arguments to one of the default three supported types first before passing them in to this
     * constructor</tt>.
     *
     * @param source the source object to be hashed.
     * @param salt the salt to use for the hash
     * @param hashIterations the number of iterations this hash will be re-hashed for attack resiliency.
     * @throws CodecException if either Object constructor argument cannot be converted into a byte array.
     * @see <a href="http://www.owasp.org/index.php/Hashing_Java" target="blank">Hashing_Java</a> 
     * for the benefits of salts and hash iterations.
     */
    public AbstractHash(Object source, Object salt, int hashIterations ) throws CodecException {
        byte[] sourceBytes = toBytes( source );
        byte[] saltBytes = null;
        if ( salt != null ) {
            saltBytes = toBytes( salt );
        }
        byte[] hashedBytes = hash( sourceBytes, saltBytes, hashIterations );
        setBytes(hashedBytes);
    }

    /**
     * Implemented by subclasses, this specifies the {@link MessageDigest MessageDigest} algorithm to use
     * when performing the hash.
     * @return the {@link MessageDigest MessageDigest} algorithm to use when performing the hash.
     */
    public abstract String getAlgorithmName();

    public byte[] getBytes() {
        return this.bytes;
    }

    /**
     * Sets the raw bytes stored by this hash instance instance.
     *
     * <p>The bytes are kept in raw form - they will not be re-hashed.  This is primarily a utility method for
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
        return hash( bytes, null, 1 );
    }

    /**
     * Hashes the specified byte array using the given <tt>salt</tt> for a single iteration.
     *
     * @param bytes the bytes to hash
     * @param salt the salt to use for the initial hash
     * @return the hashed bytes
     */
    protected byte[] hash(byte[] bytes, byte[] salt ) {
        return hash( bytes, salt, 1 );
    }

    /**
     * Hashes the specified byte array using the given <tt>salt</tt> for the specified number of iterations.
     *
     * @param bytes the bytes to hash
     * @param salt the salt to use for the initial hash
     * @param hashIterations the remaining number of times the initial hash is to be re-hashed for attack resiliency.
     * @return the hashed bytes.
     */
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) {
        MessageDigest md = getDigest(getAlgorithmName());
        if ( salt != null ) {
            md.reset();
            md.update( salt );
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
     * Simple implementation that merely returns the {@link #toHex() toHex()} value.
     *
     * @return the {@link #toHex() toHex()} value.
     */
    public String toString() {
        return toHex();
    }

    /**
     * Returns a hex-encoded string of the underlying {@link #getBytes byte array}.
     *
     * <p>This implementation caches the resulting hex string so multiple calls to this method remain performant.
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
     * <p>This implementation caches the resulting base64 string so multiple calls to this method remain performant.
     *
     * @return a Base64-encoded string of the underlying {@link #getBytes byte array}.
     */
    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeBase64ToString(getBytes());
        }
        return this.base64Encoded;
    }

    /**
     * Returns <tt>true</tt> if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, <tt>false</tt> otherwise.
     * @param o the object (Hash) to check for equality.
     * @return <tt>true</tt> if the specified object is a Hash and its {@link #getBytes byte array} is identical to
     * this Hash's byte array, <tt>false</tt> otherwise.
     */
    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }
}
