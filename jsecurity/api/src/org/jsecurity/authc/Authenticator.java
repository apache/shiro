/*
 * Copyright (C) 2005 Les A. Hazlewood, Jeremy C. Haile
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
 * An Authenticator is responsible for authenticating users by verifying submitted
 * <em>authentication tokens</em>
 *
 * <p>An <tt>authentication token</tt> is any Object representation of a user's principals and their
 * supporting credentials that an <tt>Authenticator</tt> would need to perform an authentication.
 * It is a consolidation of the user principals and credentials submitted to the system by the user.
 *
 * <p>Common implementations of an <tt>authentication token</tt> would have username/password
 * pairs, userid/public key combinations, or anything else you can think of.  The token can be
 * anything needed by an {@link Authenticator} to authenticate properly.
 *
 * <p>If you are familiar with JAAS, an <tt>authentication token</tt> behaves in the same way as a
 * {@link javax.security.auth.callback.Callback} does, but without the imposition of requiring
 * you to implement that (non-functional) marker interface or forcing JAAS login
 * symantics, such as requiring you to implement a
 * {@link javax.security.auth.callback.CallbackHandler CallbackHandler} and all the framework that
 * implies.
 *
 * <p>You are free to acquire a user's principals and credentials however you wish and
 * then submit them to the JSecurity framework in the form of any implementation.  Whether or
 * not a token will be used during authentication is determined by the
 * {@link org.jsecurity.authc.module.AuthenticationModule#supports(Class)} method.  We
 * also think the name <em>authentication token</em> more accurately reflects its true purpose
 * in a login framework, whereas <em>Callback</em> is less obvious (<tt>Callback</tt> doesn't even
 * have any methods!).
 *
 * <p><b>Implementation Note:</b> It is quite often the case that authentication submissions
 * are done in client/server systems, where the token would be created on the client tier and
 * sent over the wire to a remote server where the actual authentication process occurs.  If this
 * is the case in your system, ensure your <tt>authentication token</tt> class implements the
 * {@link java.io.Serializable} interface.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface Authenticator {

    /**
     * Authenticates a user based on the submitted <tt>authenticationToken</tt>.
     *
     * @param authenticationToken any representation of a user's principals and credentials
     * submitted during an authentication attempt.
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
    public AuthorizationContext authenticate( AuthenticationToken authenticationToken )
        throws AuthenticationException;
}
