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
import org.jsecurity.codec.CodecSupport;
import org.jsecurity.codec.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Read <a href="http://www.owasp.org/index.php/Hashing_Java">http://www.owasp.org/index.php/Hashing_Java</a> for a
 * good article on the benefits of hashing, including what a 'salt' is as well as why multiple hash iterations can
 * be useful.
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

    public AbstractHash(Object source) {
        this( source, null, 1 );
    }

    public AbstractHash(Object source, Object salt ) {
        this( source, salt, 1 );
    }

    public AbstractHash(Object source, Object salt, int hashIterations ) {
        byte[] sourceBytes = toBytes( source );
        byte[] saltBytes = null;
        if ( salt != null ) {
            saltBytes = toBytes( salt );
        }
        byte[] hashedBytes = hash( sourceBytes, saltBytes, hashIterations );
        setBytes(hashedBytes);
    }

    public abstract String getAlgorithmName();

    public byte[] getBytes() {
        return this.bytes;
    }

    public void setBytes(byte[] alreadyHashedBytes) {
        this.bytes = alreadyHashedBytes;
        this.hexEncoded = null;
        this.base64Encoded = null;
    }

    protected MessageDigest getDigest(String algorithmName) {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new IllegalStateException(msg, e);
        }
    }

    protected byte[] hash(byte[] bytes) {
        return hash( bytes, null, 1 );
    }

    protected byte[] hash(byte[] bytes, byte[] salt ) {
        return hash( bytes, salt, 1 );
    }

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

    public String toHex() {
        if (this.hexEncoded == null) {
            this.hexEncoded = Hex.encodeToString(getBytes());
        }
        return this.hexEncoded;
    }

    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeBase64ToString(getBytes());
        }
        return this.base64Encoded;
    }

    public boolean equals(Object o) {
        if (o instanceof Hash) {
            Hash other = (Hash) o;
            return Arrays.equals(getBytes(), other.getBytes());
        }
        return false;
    }
}
