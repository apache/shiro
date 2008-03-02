/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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

/**
 * An Authenticator is responsible for authenticating accounts in an application.  It
 * is one of the primary entry points into the JSecurity API.
 *
 * <p>Although not a requirement, there is usually only a single Authenticator configured for
 * an application.  Enabling Pluggable Authentication Module (PAM) behavior
 * (Two Phase Commit, etc.) is usually achieved by the single <tt>Authenticator</tt> coordinating
 * and interacting with an application-configured set of
 * {@link org.jsecurity.realm.Realm Realm}s.
 *
 * <p>Note that most JSecurity users will not interact with an <tt>Authenticator</tt> instance directly.  JSecurity's
 * default architecture is based on an overall <tt>SecurityManager</tt> which typically wraps an
 * <tt>Authenticator</tt> instance.
 *
 * @see org.jsecurity.SecurityManager
 * @see AbstractAuthenticator AbstractAuthenticator
 * @see org.jsecurity.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface Authenticator {

    /**
     * Authenticates a user based on the submitted <tt>authenticationToken</tt>.
     *
     * <p>If the authentication is successful, an {@link Account Account}
     * object is returned that represents the user's account data relevant to JSecurity.  This returned object is
     * generally used in turn to construct a <tt>Subject</tt> representing that user's access rights and
     * access to a <tt>Session</tt>
     *
     * @param authenticationToken any representation of a user's principals and credentials
     * submitted during an authentication attempt.
     *
     * @return the Account representing the authenticated user's account data.
     *
     * @throws AuthenticationException if there is any problem during the authentication process.
     * See the specific exceptions listed below to as examples of what could happen in order
     * to accurately handle these problems and to notify the user in an appropriate manner why
     * the authentication attempt failed.  Realize an implementation of this interface may or may
     * not throw those listed or may throw other AuthenticationExceptions, but the list shows
     * the most common ones.
     *
     * @see ExpiredCredentialsException
     * @see IncorrectCredentialsException
     * @see ExcessiveAttemptsException
     * @see LockedAccountException
     * @see ConcurrentAccessException
     * @see UnknownAccountException
     */
    public Account authenticate( AuthenticationToken authenticationToken )
        throws AuthenticationException;
}
