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
import org.jsecurity.codec.Hex;
import org.jsecurity.codec.support.CodecSupport;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class AbstractHash extends CodecSupport implements Hash {

    private byte[] bytes = null;

    //cache string ops to ensure multiple calls won't incur repeated overhead:
    private String hexEncoded = null;
    private String base64Encoded = null;

    public AbstractHash(){
    }

    public AbstractHash( byte[] bytes ) {
        setBytes( hash( bytes ) );
    }

    public AbstractHash( char[] chars ) {
        this( toBytes( chars ) );
    }

    public AbstractHash( String source ) {
        this( toBytes( source) );
    }

    public abstract String getAlgorithmName();

    public byte[] getBytes() {
        return this.bytes;
    }

    public void setBytes( byte[] alreadyHashedBytes ) {
        this.bytes = alreadyHashedBytes;
        this.hexEncoded = null;
        this.base64Encoded = null;
    }

    protected MessageDigest getDigest( String algorithmName ) {
        try {
            return MessageDigest.getInstance(algorithmName);
        } catch (NoSuchAlgorithmException e) {
            String msg = "No native '" + algorithmName + "' MessageDigest instance available on the current JVM.";
            throw new IllegalStateException( msg, e );
        }
    }

    protected byte[] hash( byte[] bytes ) {
        MessageDigest md = getDigest( getAlgorithmName() );
        return md.digest( bytes );
    }

    /**
     * Simple implementation that merely returns the {@link #toHex() toHex()} value.
     * @return the {@link #toHex() toHex()} value.
     */
    public String toString() {
        return toHex();
    }

    public String toHex() {
        if ( this.hexEncoded == null ) {
            this.hexEncoded = Hex.encodeToString( getBytes() );
        }
        return this.hexEncoded;
    }

    public String toBase64() {
        if (this.base64Encoded == null) {
            //cache result in case this method is called multiple times.
            this.base64Encoded = Base64.encodeBase64ToString( getBytes() );
        }
        return this.base64Encoded;
    }

    public boolean equals( Object o ) {
        if ( o instanceof Hash ) {
            Hash other = (Hash)o;
            return Arrays.equals( getBytes(), other.getBytes() );
        }
        return false;
    }
}
