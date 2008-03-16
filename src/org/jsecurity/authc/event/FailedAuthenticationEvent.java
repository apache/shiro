/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
