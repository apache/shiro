/*
 * Copyright (C) 2005 Jeremy C. Haile
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

package org.jsecurity.ri.authc.module.dao;

import java.util.Collection;

/**
 * An interface containing the information required by the {@link DAOAuthenticationModule}
 * to authenticate a user and construct a {@link org.jsecurity.authz.AuthorizationContext} for the user.
 *
 * @see DAOAuthenticationModule
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface AuthenticationInfo {

    /**
     * The user's username principal used to uniquely identify the user.
     * @return the user's username who is being authenticated.
     */
    public String getUsername();

    /**
     * The user's password as stored in the system.  This password may be
     * encrypted, in which case the {@link DAOAuthenticationModule} must be
     * informed of the encryption algorithm used to encrypt the password.
     * @return the user's password as stored in the system.
     */
    public char[] getPassword();

    /**
     * A collection of role identifiers that represent the roles that this
     * user is a member of.  These roles will be used to determine the
     * authorization privileges of the user being authenticated.
     * @return a collection of role identifiers (typically <tt>String</tt>
     * names of roles)
     */
    public Collection<String> getRoles();


    /**
     * Determines if the user's account is locked, meaning that the user is
     * not allowed to log in due to a manual or automatic lockout.
     * @return true if the user's account is locked and the user should be
     * denied authorization, false otherwise.
     */
    public boolean isAccountLocked();


    /**
     * Determines if the user's credentials (password) has expired and must be
     * changed before login is allowed.
     * @return true if the user's credentials are expired and the user should
     * be denied authentication, false otherwise.
     */
    public boolean isCredentialsExpired();


    /**
     * Determines if the user is allowed to concurrently login from two
     * unique sessions.  For example, if Joe needs the ability to leave
     * an account logged in at home and still log in from work, then
     * concurrent logins should be enabled.  This feature is mainly intended
     * to prevent account sharing where a user distributes his password to
     * others who log in concurrently.
     * @return true if the user should be allowed to login concurrently,
     * false otherwise.
     */
    public boolean isConcurrentLoginsAllowed();

}