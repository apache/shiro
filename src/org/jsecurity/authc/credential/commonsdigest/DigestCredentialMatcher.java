/*
 * Copyright (C) 2005-2007 Jeremy Haile
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

package org.jsecurity.authc.credential.commonsdigest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.jsecurity.authc.credential.CredentialMatcher;

import java.util.Arrays;

/**
 * A superclass for any digest-based password matcher that provides support
 * for encoding passwords in Base64 or Hex.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public abstract class DigestCredentialMatcher implements CredentialMatcher {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Set to true if the passwords are encoded using Base64 encoding.  If
     * this is false, the passwords are assumed to be encoded in hex format.
     */
    private boolean base64Encoded;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public boolean isBase64Encoded() {
        return base64Encoded;
    }


    public void setBase64Encoded(boolean base64Encoded) {
        this.base64Encoded = base64Encoded;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * Calls the abstract {@link #doDigest(byte[])} method to digest the provided password
     * and compares it with the stored password after encoding the passwords using hex
     * or base64 encodings.
     * @param providedPassword the unhashed password char array (char[]) provided by the user.
     * @param storedPassword the hashed password char array (char[]) stored in the system.
     * @return true if the hashes match, false otherwise.
     */
    public boolean doCredentialsMatch( Object providedPassword,
                                       Object storedPassword ) {

        char[] providedPasswordChars = castToCharArray( providedPassword );
        char[] storedPasswordChars = castToCharArray( storedPassword );

        byte[] digestedBytes = doDigest( charsToBytes( providedPasswordChars ) );

        if( isBase64Encoded() ) {
            byte[] encodedPasswordBase64 = Base64.encodeBase64( digestedBytes );
            byte[] storedPasswordBytes = charsToBytes( storedPasswordChars );
            return Arrays.equals( encodedPasswordBase64, storedPasswordBytes );
        } else {
            char[] encodedPasswordHex = Hex.encodeHex( digestedBytes );
            return Arrays.equals( encodedPasswordHex, storedPasswordChars );
        }
    }


    /**
     * Converts an array of characters to bytes.
     * @param passwd the password being converted.
     * @return an array of bytes that match the characters given.
     */
    protected byte[] charsToBytes( char[] passwd ) {
        byte[] buf = new byte[passwd.length];
        for (int i = 0; i < passwd.length; i++) {
            buf[i] = (byte) passwd[i];
        }
        return buf;
    }

    protected char[] bytesToChars( byte[] bytes ) {
        char[] buf = new char[bytes.length];
        for( int i = 0; i < bytes.length; i++ ) {
            buf[i] = (char)bytes[i];
        }
        return buf;
    }

    public char[] encodeToChars( String s ) {
        char[] chars = castToCharArray( s );
        byte[] digested = doDigest( charsToBytes( chars ) );
        if ( isBase64Encoded() ) {
            byte[] encoded = Base64.encodeBase64( digested );
            return bytesToChars( encoded );
        } else {
            return Hex.encodeHex( digested );
        }
    }

    public byte[] encodeToBytes( String s ) {
        char[] chars = castToCharArray( s );
        byte[] digested = doDigest( charsToBytes( chars ) );
        if ( isBase64Encoded() ) {
            return Base64.encodeBase64( digested );
        } else {
            return charsToBytes( Hex.encodeHex( digested ) );
        }
    }

    public String encode( String s ) {
        return new String( encodeToChars( s ) );   
    }


    /**
     * Performs the actual digest of the provided password - to be implemented
     * by subclasses.
     * @param providedPassword the bytes of the provided password.
     * @return a hash of the given password bytes.
     */
    protected abstract byte[] doDigest( byte[] providedPassword );


    /**
     * Converts given credentials into a char[] if they are of type String or char[].
     * @param credential the credential.
     * @return the credential in char[] form.
     */
    protected char[] castToCharArray(Object credential) {
        char[] chars;

        if( credential instanceof String ) {
            chars = ((String)credential).toCharArray();

        } else if( credential instanceof char[] ) {
            chars = (char[])credential;

        } else {
            throw new IllegalArgumentException( "This credential matcher only supports credentials of type String or char[]." );
        }

        return chars;
    }

}