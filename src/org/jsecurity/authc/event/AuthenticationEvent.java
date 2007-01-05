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

import java.security.Principal;
import java.util.Date;
import java.util.EventObject;

/**
 * General event concerning the authentication of a particular subject (aka user or account).
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AuthenticationEvent extends EventObject {

    /**
     * The time at which this event took place.
     */
    protected Date timestamp = new Date();

    /**
     * The principal of the user associated with this event.
     */
    protected final Principal principal;

    /**
     * Creates a new authentication event.
     *
     * <p>As a clarification, when constructing an instance of this class, the given Principal is
     * usually the identity associated with the authentication attempt, such as a username or id.
     *
     * <p>As events are often logged, it is recommended that the argument should not represent a
     * password (which is technically considered a credential, not a principal) to avoid the
     * possibility of logging the password in clear text, which may be viewed by 3rd parties.
     * Of course, this is not a requirement, just a recommendation.
     *
     * @param principal the <tt>Principal</tt> identity associated with the authentication attempt.
     */
    public AuthenticationEvent( Principal principal ) {
        super( principal );
        this.principal = principal;
    }


    /**
     * Creates a new authentication event with the given source and the given principal.
     *
     * <p>As a clarification, when constructing an instance of this class, the given Principal is
     * usually the identity associated with the authentication attempt, such as a username or id.
     *
     * <p>As events are often logged, it is recommended that the argument should not represent a
     * password (which is technically considered a credential, not a principal) to avoid the
     * possibility of logging the password in clear text, which may be viewed by 3rd parties.
     * Of course, this is not a requirement, just a recommendation.
     *
     * @param source the component responsible for the event.
     * @param principal the principal of the account identity associated with the authentication.
     */
    public AuthenticationEvent( Object source, Principal principal ) {
        super( source );
        if ( principal == null ) {
            String msg = "Principal argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
        this.principal = principal;
    }

    /**
     * Returns the timestamp associated with this event.
     *
     * @return the timestamp associated with this event.
     */
    public Date getTimestamp() {
        return timestamp;
    }

    /**
     * Returns the principal (aka subject identity) associated with the authentication event.
     *
     * @return the the principal (aka subject identity) associated with the authentication event.
     */
    public Principal getPrincipal() {
        return this.principal;
    }


}
