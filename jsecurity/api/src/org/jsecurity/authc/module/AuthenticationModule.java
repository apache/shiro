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
package org.jsecurity.authc.module;

import org.jsecurity.authc.Authenticator;

/**
 * An AuthenticationModule is an {@link org.jsecurity.authc.Authenticator} that can support specific types of
 * <em>authentication tokens</em>.  Please see the {@link org.jsecurity.authc.Authenticator} class API to understand
 * how <tt>authentication token</tt>s function.
 *
 * <p>An implementation of this class can be used
 *    in any JSecurity compatible PAM (Pluggable Authentication Module) implementation.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public interface AuthenticationModule extends Authenticator {

    /**
     * Returns true if this module can authenticate subjects with <tt>authentication token</tt>
     * instances of the specified Class, false otherwise.
     *
     * <p>If the module does not support the specified type, it will not be used to authenticate any
     * tokens of that type.
     *
     * @param tokenClass the <tt>authentication token</tt> Class to check for support.
     *
     * @return true if this module can authenticate subjects with tokens of the
     * specified class, false otherwise.
     */
    boolean supports( Class tokenClass );

}
