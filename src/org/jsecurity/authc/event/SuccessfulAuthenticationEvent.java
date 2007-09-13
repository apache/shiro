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

/**
 * Event triggered when the {@link #getPrincipal() associated subject} authenticates
 * successfully.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SuccessfulAuthenticationEvent extends AuthenticationEvent {

    /**
     * Creates a SuccessfulAuthenticationEvent for the specified subject who successfully logged-in to the system.
     * @param principal the subject identifier of the subject that successfully logged-in.
     */
    public SuccessfulAuthenticationEvent( Object principal ) {
        super( principal );
    }

    /**
     * Creates a SuccessfulAuthenticationEvent for the specified subject who successfully logged-in to the system,
     * generated or caused by the specified <tt>source</tt> argument.
     * @param source the component that generated or caused the event.
     * @param principal the subject identifier of the subject that succesfully logged-in.
     */
    public SuccessfulAuthenticationEvent( Object source, Object principal ) {
        super( source, principal );
    }

}
