/*
 * Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.ri.authc.credential;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

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

    protected boolean isBase64Encoded() {
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
     * @param providedPasswordCharArray the unhashed password char array (char[]) provided by the user.
     * @param storedPasswordCharArray the hashed password char array (char[]) stored in the system.
     * @return true if the hashes match, false otherwise.
     */
    public boolean doCredentialsMatch( Object providedPasswordCharArray,
                                       Object storedPasswordCharArray ) {

        char[] providedPassword = (char[])providedPasswordCharArray;
        char[] storedPassword = (char[])storedPasswordCharArray;

        byte[] digestedBytes = doDigest( charsToBytes( providedPassword ) );

        if( isBase64Encoded() ) {
            byte[] encodedPasswordBase64 = Base64.encodeBase64( digestedBytes );
            byte[] storedPasswordBytes = charsToBytes( storedPassword );
            return Arrays.equals( encodedPasswordBase64, storedPasswordBytes );
        } else {
            char[] encodedPasswordHex = Hex.encodeHex( digestedBytes );
            return Arrays.equals( encodedPasswordHex, storedPassword );
        }
    }


    /**
     * Converts an array of characters to bytes.
     * @param passwd the password being converted.
     * @return an array of bytes that match the characters given.
     */
    private byte[] charsToBytes( char[] passwd ) {
        byte[] buf = new byte[passwd.length];
        for (int i = 0; i < passwd.length; i++) {
            buf[i] = (byte) passwd[i];
        }
        return buf;
    }


    /**
     * Performs the actual digest of the provided password - to be implemented
     * by subclasses.
     * @param providedPassword the bytes of the provided password.
     * @return a hash of the given password bytes.
     */
    protected abstract byte[] doDigest( byte[] providedPassword );


}