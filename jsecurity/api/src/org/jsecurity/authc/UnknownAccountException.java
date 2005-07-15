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
package org.jsecurity.authc;

/**
 * Thrown when attempting to authenticate with a principal that doesn't exist in the system (e.g.
 * by specifying a username that doesn't relate to a user account).
 *
 * <p>Whether or not an application wishes to alert a user logging in to the system of this fact is
 * at the discretion of those responsible for designing the view and what happens when this
 * case occurs.
 *
 * @author Les Hazlewood
 */
public class UnknownAccountException extends AccountException {

    public UnknownAccountException() {
        super();
    }

    public UnknownAccountException( String message ) {
        super( message );
    }

    public UnknownAccountException( Throwable cause ) {
        super( cause );
    }

    public UnknownAccountException( String message, Throwable cause ) {
        super( message, cause );
    }
}
