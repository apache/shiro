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
package org.jsecurity.authc.event;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * Event triggered when an authentication attempt fails.  If an exception is thrown indicating
 * the attempt failure, it will be accessible via the {@link #getCause()} method so one
 * may determine why the authentication failed.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class FailedAuthenticationEvent extends AttemptedAuthenticationEvent {

    private AuthenticationException cause = null;

    public FailedAuthenticationEvent( AuthenticationToken token ) {
        super( token );
    }

    public FailedAuthenticationEvent( AuthenticationToken token, Object source ) {
        super( token, source );
    }

    public FailedAuthenticationEvent( AuthenticationToken token, AuthenticationException cause ) {
        this( token );
        setCause( cause );
    }

    public FailedAuthenticationEvent( AuthenticationToken token, Object source, AuthenticationException cause ) {
        super( token, source );
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
