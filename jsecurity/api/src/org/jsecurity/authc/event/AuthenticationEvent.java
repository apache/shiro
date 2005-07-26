/*
 * Copyright (C) 2005 Jeremy Haile
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

import java.security.Principal;
import java.util.Calendar;
import java.util.EventObject;

/**
 * General event concerning the authentication of a particular user.
 *
 * todo We need to decide whether or not to extend EventObject.  -JCH
 *
 * @author Jeremy Haile
 */
public abstract class AuthenticationEvent extends EventObject {

    /**
     * The time at which this event took place.
     */
    protected Calendar timestamp = Calendar.getInstance();

    /**
     * The principal of the user associated with this event.
     */
    protected final Principal principal;


    /**
     * Creates a new authentication event with a dummy source and the given
     * principal.
     *
     * @param source the source of this event, typically the
     * {@link org.jsecurity.authc.Authenticator} responsible for the authentication
     * event.
     * @param principal the principal of the authenticated user.
     */
    public AuthenticationEvent( Object source, Principal principal ) {
        super( source );
        this.principal = principal;
    }

    /**
     * Returns the timestamp associated with this event.
     *
     * @return the timestamp associated with this event.
     */
    public Calendar getTimestamp() {
        return timestamp;
    }

}
