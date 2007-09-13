/*
 * Copyright (C) 2005-2007 Les Hazlewood
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

import java.io.Serializable;

/**
 * <p>An <tt>AuthenticationToken</tt> is a consolidation of an account's principals and supporting
 * credentials submitted by a user during an authentication attempt.
 *
 * <p>The token is submitted to an {@link Authenticator Authenticator} via the
 * {@link Authenticator#authenticate(AuthenticationToken) authenticate(token)} method.  The
 * Authenticator then executes the authentication/log-in process.
 *
 * <p>Common implementations of an <tt>AuthenticationToken</tt> would have username/password
 * pairs, userid/public key combinations, or anything else you can think of.  The token can be
 * anything needed by an {@link Authenticator} to authenticate properly.
 *
 * <p>Because applications represent user data and credentials in different ways, implementations
 * of this interface are application-specific.  You are free to acquire a user's principals and
 * credentials however you wish (e.g. web form, Swing form, fingerprint identification, etc) and
 * then submit them to the JSecurity framework in the form of an implementation of this
 * interface.
 *
 * <p>If your application's authentication process is  username/password based
 * (like most), instead of implementing this interface yourself, take a look at the
 * {@link UsernamePasswordToken UsernamePasswordToken} class, as it is probably sufficient for your needs.
 *
 * <p>If you are familiar with JAAS, an <tt>AuthenticationToken</tt> replaces the concept of a
 * {@link javax.security.auth.callback.Callback}, and  defines meaningful behavior
 * (<tt>Callback</tt> is just a marker interface, and of little use).  We
 * also think the name <em>AuthenticationToken</em> more accurately reflects its true purpose
 * in a login framework, whereas <em>Callback</em> is less obvious.
 *
 * @see UsernamePasswordToken
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface AuthenticationToken extends Serializable {

    /**
     * Returns the account identity submitted during the authentication process.
     *
     * <p>Most application authentications are username/password based and have this
     * object represent a username.  If this is the case for your application,
     * take a look at the {@link UsernamePasswordToken UsernamePasswordToken}, as it is probably
     * sufficient for your use.
     *
     * <p>Ultimately, the object returned is application specific and can represent
     * any account identity (user id, X.509 certificate, etc).
     *
     * @return the account identity submitted during the authentication process.
     *
     * @see UsernamePasswordToken
     */
    Object getPrincipal();

    /**
     * Returns the credentials submitted by the user during the authentication process that verifies
     * the submitted {@link #getPrincipal() account identity}.
     *
     * <p>Most application authentications are username/password based and have this object
     * represent a submitted password.  If this is the case for your application,
     * take a look at the {@link UsernamePasswordToken UsernamePasswordToken}, as it is probably
     * sufficient for your use.
     *
     * <p>Ultimately, the credentials Object returned is application specific and can represent
     * any credential mechanism.
     *
     * @return the credential submitted by the user during the authentication process.
     */
    Object getCredentials();

}