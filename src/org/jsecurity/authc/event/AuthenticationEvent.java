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

import org.jsecurity.SecurityEvent;

/**
 * General event concerning the authentication of a particular Subject (aka User).
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AuthenticationEvent extends SecurityEvent {

    protected Object principals = null;

    /**
     * Creates a new <tt>AuthenticationEvent</tt> based on the Subject identified by the given principals.
     * @param principals the identifiying data for the Subject associated with this event.
     */
    public AuthenticationEvent( Object principals ) {
        this( principals, principals );
    }


    /**
     * Creates a new authentication event with the given source and the given <tt>AuthenticationToken</tt> submitted
     * for the Authentication attempt.
     *
     * @param principals the identifiying data for the Subject associated with this event.
     * @param source the component responsible for generating the event.
     * associated with the authentication attempt
     */
    public AuthenticationEvent( Object principals, Object source ) {
        super( source );
        if ( principals == null ) {
            String msg = "principals argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
        this.principals = principals;
    }

    /**
     * Returns the principals (aka Subject identity) associated with the authentication event.
     *
     * @return the the principals (aka subject identity) associated with the authentication event.
     */
    public Object getPrincipals() {
        return this.principals;
    }

}
