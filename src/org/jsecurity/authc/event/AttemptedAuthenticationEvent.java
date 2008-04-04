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

import org.jsecurity.authc.AuthenticationToken;

/**
 * An <tt>AuthenticationEvent</tt> generated in response to an authentication attempt.
 *
 * <p>Its subclasses provide more information as to if the attempt was successful or not and related data in either
 * case</p>
 *
 * <p>The <tt>AuthenticationToken</tt> that was submitted during the authentication attempt that caused this
 * event to be generated is accessible via the {@link #getToken() getToken()} method.</p>
 *
 * @see SuccessfulAuthenticationEvent
 * @see FailedAuthenticationEvent
 *
 * @since 0.9
 */
public abstract class AttemptedAuthenticationEvent extends AuthenticationEvent {

    protected final AuthenticationToken token; //authentication token submitted during the authentication attempt.

    /**
     * Creates a new event triggered during an authentication attempt based on the submitted
     * <tt>AuthenticationToken</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     */
    public AttemptedAuthenticationEvent( AuthenticationToken token ) {
        super( token.getPrincipal() );
        this.token = token;
    }


    /**
     * Creates a new authentication event with the given source and the given <tt>AuthenticationToken</tt> submitted
     * during the authentication attempt.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     * @param source the component responsible for generating the event.
     * associated with the authentication attempt
     */
    public AttemptedAuthenticationEvent( AuthenticationToken token, Object source ) {
        super( source );
        if ( token == null ) {
            String msg = "AuthenticationToken argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
        this.token = token;
    }

    /**
     * Returns the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     * @return the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     */
    public AuthenticationToken getToken() {
        return this.token;
    }

}
