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
package org.jsecurity.authc.credential.support;

import org.jsecurity.authc.credential.CredentialMatcher;

import java.util.Arrays;

/**
 * Simple implementation of the {@link CredentialMatcher} interface that
 * compares two plain text passwords.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class PlainTextCredentialMatcher implements CredentialMatcher {


    /**
     * Compares two plain text passwords.  Both arguments are expected to be either a char array or a String.
     * 
     * @param providedPassword the user-provided password as a String or char array (char[])
     * @param storedPassword the password stored in the system as a String or char array (char[]).
     * @return true if the passwords are equal, false otherwise.
     */
    public boolean doCredentialsMatch( Object providedPassword,
                                       Object storedPassword ) {
        char[] providedPasswordChars = castToCharArray(providedPassword);
        char[] storedPasswordChars = castToCharArray(storedPassword);

        return Arrays.equals( providedPasswordChars, storedPasswordChars );
    }


    /**
     * Converts given credentials into a char[] if they are of type String or char[].
     * @param credential the credential.
     * @return the credential in char[] form.
     * @throws IllegalArgumentException if the argument is not a String or char array (char[])
     */
    private char[] castToCharArray(Object credential) throws IllegalArgumentException {
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