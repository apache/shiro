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
package org.jsecurity.ri.authc.event;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.event.AuthenticationEvent;

import java.security.Principal;

/**
 * Event triggered when an authentication attempt fails.  If an exception is thrown indicating
 * the attempt failure, it will be accessible via the {@link #getCause()} method so one
 * may determine why the authentication failed.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class FailedAuthenticationEvent extends AuthenticationEvent {

    private AuthenticationException cause = null;

    public FailedAuthenticationEvent( Principal principal ) {
        super( principal );
    }

    public FailedAuthenticationEvent( Object source, Principal principal ) {
        super( source, principal );
    }

    public FailedAuthenticationEvent( Principal principal, AuthenticationException cause ) {
        this( principal );
        setCause( cause );
    }

    public FailedAuthenticationEvent( Object source, Principal principal, AuthenticationException cause ) {
        super( source, principal );
        setCause( cause );
    }

    public AuthenticationException getCause() {
        return this.cause;
    }

    protected void setCause( AuthenticationException cause ) {
        if ( cause == null ) {
            String msg = "cause argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
        this.cause = cause;
    }

}
