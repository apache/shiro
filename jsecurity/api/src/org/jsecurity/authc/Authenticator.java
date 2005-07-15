/*
 * Copyright (C) 2005 Les A. Hazlewood
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
package org.jsecurity.authc;

import org.jsecurity.authz.AuthorizationContext;

/**
 * An Authenticator is responsible for authenticating users by verifying
 * {@link AuthenticationToken}s.  An AuthenticationToken is created during the authentication
 * process (e.g. after submittal of user principals and credentials) and then submitted to one
 * or more <tt>Authenticator</tt>s.
 *
 * @author Les Hazlewood
 */
public interface Authenticator {

    /**
     * Authenticates a user based on the submitted <tt>AuthenticationToken</tt>.
     *
     * @param token the AuthenticationToken representing the principals and credentials that
     * were submitted by the user.
     *
     * @return the AuthorizationContext maintaining the authenticated user's access controls.
     *
     * @throws AuthenticationException if there is any problem during the authentication process.
     * See the specific exceptions listed below to accurately handle these problems and to
     * notify the user in an appropriate manner why the authentication attempt failed.
     *
     * @see ExpiredCredentialException
     * @see IncorrectCredentialException
     * @see ExcessiveAttemptsException
     * @see LockedAccountException
     * @see ConcurrentAccessException
     * @see UnknownAccountException
     */
    public AuthorizationContext authenticate( AuthenticationToken token ) throws AuthenticationException;
}
