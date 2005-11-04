/*
 * Copyright (C) 2005 Les Hazlewood, Jeremy C. Haile
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
 * An Authenticator is responsible for authenticating accounts in an application.  It
 * is one of the primary entry points into the JSecurity API.
 *
 * <p>Although not a requirement, there is usually only a single Authenticator configured for
 * an application.  Enabling Pluggable Authentication Module (PAM) behavior
 * (Two Phase Commit, etc.) is usually achieved by the single <tt>Authenticator</tt> coordinating
 * and interacting with an application-configured set of
 * {@link org.jsecurity.authc.module.AuthenticationModule AuthenticationModule}s.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface Authenticator {

    /**
     * Authenticates a user based on the submitted <tt>authenticationToken</tt>.
     *
     * <p>If the authentication is successful, an {@link AuthorizationContext AuthorizationContext}
     * is returned that represents the authenticated user's access rights.
     *
     * Because authorization operations can only occur under the context of a known and valid
     * identity, an account's <tt>AuthorizationContext</tt> is only available after a successful
     * log-in, when the identity has been verified.
     *
     * @param authenticationToken any representation of a user's principals and credentials
     * submitted during an authentication attempt.
     *
     * @return the AuthorizationContext maintaining the authenticated user's access rights.
     *
     * @throws AuthenticationException if there is any problem during the authentication process.
     * See the specific exceptions listed below to as examples of what could happen in order
     * to accurately handle these problems and to notify the user in an appropriate manner why
     * the authentication attempt failed.  Realize an implementation of this interface may or may
     * not throw those listed or may throw other AuthenticationExceptions, but the list shows
     * the most common ones.
     *
     * @see ExpiredCredentialException
     * @see IncorrectCredentialException
     * @see ExcessiveAttemptsException
     * @see LockedAccountException
     * @see ConcurrentAccessException
     * @see UnknownAccountException
     *
     * @see org.jsecurity.authc.module.AuthenticationModule
     */
    public AuthorizationContext authenticate( AuthenticationToken authenticationToken )
        throws AuthenticationException;
}
