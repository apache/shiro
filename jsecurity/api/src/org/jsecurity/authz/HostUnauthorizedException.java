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
package org.jsecurity.authz;

import java.net.InetAddress;

/**
 * Thrown when a particular client (i.e. host address) has not been enabled to access the system
 * or if the client has been enabled access but is not permitted to perform a particluar operation
 * or access a particular resource.
 *
 * @see org.jsecurity.session.SessionAccessor#start(java.net.InetAddress)
 *
 * @author Les Hazlewood
 */
public class HostUnauthorizedException extends UnauthorizedException {

    public HostUnauthorizedException() {
        super();
    }

    public HostUnauthorizedException( InetAddress hostAddress ) {
        this( "The system is not cofigured to allow access for host [" +
              hostAddress.getHostAddress() + "]" );
    }

    public HostUnauthorizedException( String s ) {
        super( s );
    }

    public HostUnauthorizedException( Throwable cause ) {
        super( cause );
    }

    public HostUnauthorizedException( String message, Throwable cause ) {
        super( message, cause );
    }
}
