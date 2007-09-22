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

import java.net.InetAddress;

/**
 * Authentication token that also preserves the IP from where the authentication attempt is taking place.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface InetAuthenticationToken extends AuthenticationToken {

    /**
     * Returns the InetAddress from where the authentication attempt is occurring.  May be null if the IP address
     * is ignored or unknown, in which case, it is up to the Authenticator processing the token to determine if
     * it is valid without the IP.
     * @return the InetAddress from where the authentication attempt is occurring.
     */
    InetAddress getInetAddress();
}
