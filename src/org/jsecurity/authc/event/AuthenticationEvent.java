/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
