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

package org.jsecurity.authc;

import java.security.Principal;

/**
 * A marker interface that provides type-safety for code passing arguments to
 * the {@link Authenticator#authenticate(AuthenticationToken)} method.  Although
 * this interface does not define any behavior for implementing classes, it does
 * provide type-safety when calling the authentication methods.
 *
 * @see UsernamePasswordToken
 *
 * @since 1.0
 * @author Jeremy Haile
 */
public interface AuthenticationToken {

    /**
     * Returns the account identity submitted during the authentication process.
     *
     * <p>Most application authentications are username/password based and have this
     * <tt>Principal</tt> represent a username.  If this is the case for your application,
     * take a look at the {@link UsernamePasswordToken UsernamePasswordToken}, as it is probably
     * sufficient for your use.
     *
     * <p>Ultimately, the <tt>Principal</tt> returned is application specific and can represent
     * any account identity (user id, X.509 certificate, etc).
     *
     * @return the account identity submitted during the authentication process.
     *
     * @see UsernamePasswordToken
     */
    Principal getPrincipal();

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
     * @return the credential submitted by the user during the authenticatin process.
     */
    Object getCredentials();

}