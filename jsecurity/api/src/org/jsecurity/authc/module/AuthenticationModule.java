/*
 * Copyright (C) 2005 Les Hazlewood
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

package org.jsecurity.authc.module;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * An <tt>AuthenticationModule</tt> is a pluggable component that can communicate to a specific
 * sub-system to acquire authentication data.  This data is used during the authentication process
 * to verify if an authentication attempt is successful or not.
 *
 * <p>An <tt>AuthenticationModule</tt> is sometimes called in other systems an
 * <em>authentication provider</em>.  This means that the component has the abiblity to provide
 * access to authentication data in a environment-specific manner (e.g. LDAP, RDBMS, fingerprint,
 * etc.).  We chose to use the name <tt>Module</tt> for intuition's sake: JSecurity has the
 * ability to use any number of these modules either alone, or in conjunction with each other, to
 * perform an authentication.  This is known in the security world as
 * PAM (Pluggable Authentication Module).  Since JSecurity is designed to support PAM
 * architectures, we feel this name more accurately describes its purpose in a coordinated
 * security framework than the term 'authentication provider'.
 *
 * <p>An <tt>AuthenticationModule</tt> typically has a 1-to-1 correspondence with a
 * <em>type</em> of back-end authentication system.  That is, you usually will see 1 implementation
 * that can talk to an LDAP directory, anther implementation that uses raw JDBC, or another that
 * uses the Hibernate API, etc.
 *
 * <p>The coordination of how one or more modules execute is performed by an
 * {@link org.jsecurity.authc.Authenticator Authenticator} implementation, which typically
 * implements PAM behavior.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface AuthenticationModule {

    /**
     * Returns true if this module can authenticate subjects with
     * {@link AuthenticationToken AuthenticationToken} instances of the specified Class,
     * false otherwise.
     *
     * <p>If the module does not support the specified type, it will not be used to authenticate any
     * tokens of that type.
     *
     * @param tokenClass the <tt>AuthenticationToken</tt> Class to check for support.
     *
     * @return true if this module can authenticate subjects represented by tokens of the
     * specified class, false otherwise.
     */
    boolean supports( Class tokenClass );

    /**
     * Returns account information for the account associated with the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     *
     * @param token the application-specific representation of an account principal and credentials.
     *
     * @return the account information for the account associated with the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     *
     * @throws AuthenticationException if there is an error obtaining obtaining or
     * constructing an AuthenticationInfo based on the specified <tt>token</tt>.
     */
    AuthenticationInfo getAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException;

}
