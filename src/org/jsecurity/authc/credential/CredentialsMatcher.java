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
package org.jsecurity.authc.credential;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationToken;

/**
 * Interface that can be implemented by classes that can determine if an AuthenticationToken's provided
 * credentials matches a corresponding account's credentials stored in the system.
 *
 * <p>As a common example, an implementation of this interface might verify a user-submitted
 * text password with a corresponding account password stored in the system.
 *
 * @see SimpleCredentialsMatcher
 * @see AllowAllCredentialsMatcher
 * @see Md5CredentialsMatcher
 * @see ShaCredentialsMatcher
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface CredentialsMatcher {

    /**
     * Determines if the provided credential matches the stored credential.
     * @param token
     * @param account @return true if the credentials match, false if they do not match.
     */
    boolean doCredentialsMatch( AuthenticationToken token, Account account );

}