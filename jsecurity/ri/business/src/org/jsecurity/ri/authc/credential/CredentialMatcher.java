/*
* Copyright (C) 2005 Jeremy C. Haile, Les Hazlewood
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

/**
 * Interface that can be implemented by classes that can determine if a provided
 * credential matches a corresponding account credential stored in the system.
 *
 * <p>As a commone example, an implementation of this interface might verify a user-submitted
 * text password with a corresponding account password stored in the system.
 *
 * @see PlainTextCredentialMatcher
 * @see Md5CredentialMatcher
 * @see ShaCredentialMatcher
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface CredentialMatcher {

    /**
     * Determines if the provided credential matches the stored credential.
     * @param providedCredential the credential provided by the user.
     * @param storedCredential the credential stored in the system (possibly encrypted) used to
     * verify the <tt>providedCredential</tt>.
     * @return true if the credentials match, false if they do not match.
     */
    boolean doCredentialsMatch( Object providedCredential, Object storedCredential );

}