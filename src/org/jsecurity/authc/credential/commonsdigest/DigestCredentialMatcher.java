/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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
 * @author Les Hazlewood
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

    /**
     * Returns <tt>true</tt> if digested values will be Base64 encoded, <tt>false</tt> if they will be
     * Hex encoded.
     *
     * <p>Default value is <tt>false</tt> such that Hex encoding is enabled by default.
     *
     * @return <tt>true</tt> if digested values will be Base64 encoded, <tt>false</tt> otherwise.
     */
    public boolean isBase64Encoded() {
        return base64Encoded;
    }


    /**
     * Sets if digested values will be Base 64 encoded.
     * 
     * <p>The implementation's default value is <tt>false</tt>, meaning Hex encoding is used by default.
     *
     * @param base64Encoded whether or not to Base 64 encode digested values.
     */
    public void setBase64Encoded(boolean base64Encoded) {
        this.base64Encoded = base64Encoded;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Calls the abstract {@link #doDigest(byte[])} method to digest the provided password, then encodes this
     * digested value to to Hex or Base64 (depending on the {@link #isBase64Encoded() isBase64Encoded()} value), and
     * then returns the equals comparison result of this digested/encoded value with the given <tt>storedPassword</tt>
     * argument.
     * 
     * @param providedPassword the unhashed password char array (char[]) provided by the user.  This will be digested
     * and encoded before comparison with the <tt>storedPassword</tt> argument.
     * @param storedPassword the already digested and encoded password char array (char[]) stored in the system.
     * @return true if the hashes are equal, false otherwise.
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
     * Utility method that converts the given char array to a byte array.
     *
     * @param passwd the char array to converted.
     * @return the input array as an array of bytes.
     */
    protected byte[] charsToBytes( char[] passwd ) {
        byte[] buf = new byte[passwd.length];
        for (int i = 0; i < passwd.length; i++) {
            buf[i] = (byte) passwd[i];
        }
        return buf;
    }

    /**
     * Utility method that converts the given byte array to a char array.
     *
     * @param bytes the byte array to be converted
     * @return the input array as a char array
     */
    protected char[] bytesToChars( byte[] bytes ) {
        char[] buf = new char[bytes.length];
        for( int i = 0; i < bytes.length; i++ ) {
            buf[i] = (char)bytes[i];
        }
        return buf;
    }

    /**
     * Encodes the given String via the digest algorithm and returns the result as a char array.
     * @param s the String to encode.
     * @return the encoded result as a char array.
     */
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

    /**
     * Encodes the given String via the digest algorithm and returns the result as a byte array.
     * 
     * @param s the String to encode.
     * @return the encoded result as a byte array.
     */
    public byte[] encodeToBytes( String s ) {
        char[] chars = castToCharArray( s );
        byte[] digested = doDigest( charsToBytes( chars ) );
        if ( isBase64Encoded() ) {
            return Base64.encodeBase64( digested );
        } else {
            return charsToBytes( Hex.encodeHex( digested ) );
        }
    }

    /**
     * Encodes the given String via the digest algorithm and returns the result as a byte array.
     * This can also be used as a utility method to see what the resulting encoded value of an input would be.
     *
     * @param s the String to encode
     * @return the encoded value as transformed by the underlying digest algorithm.
     */
    public String encode( String s ) {
        return new String( encodeToChars( s ) );   
    }


    /**
     * Performs the actual digest of the provided password.
     * @param providedPassword the bytes of the provided password.
     * @return a hash of the given password bytes.
     */
    protected abstract byte[] doDigest( byte[] providedPassword );


    /**
     * Converts given credentials into a char[] if they are of type String or char[].
     * @param credential the credential.
     * @return the credential in char[] form.
     * @throws IllegalArgumentException if the method argument is not of type <tt>char[]</tt> or <tt>String</tt>.
     */
    protected char[] castToCharArray(Object credential) throws IllegalArgumentException {
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