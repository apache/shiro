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

import java.util.Arrays;

/**
 * Simple implementation of the {@link CredentialMatcher} interface that
 * compares two plain text passwords.
 *
 * todo Make this class accept char[] or Strings.. or at least give a better error message than a ClassCastException
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class PlainTextCredentialMatcher implements CredentialMatcher {


    /**
     * Compares two plain text passwords.
     * 
     * @param providedPasswordCharArray the user-provided password as a char array (char[])
     * @param storedPasswordCharArray the password stored in the system as a char array (char[]).
     * @return true if the passwords match, false otherwise.
     */
    public boolean doCredentialsMatch( Object providedPasswordCharArray,
                                       Object storedPasswordCharArray ) {
        char[] providedPassword = (char[])providedPasswordCharArray;
        char[] storedPassword = (char[])storedPasswordCharArray;
        return Arrays.equals( providedPassword, storedPassword );
    }
}