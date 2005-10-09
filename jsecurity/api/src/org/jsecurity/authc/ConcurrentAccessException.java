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
 * Thrown when an authentication attempt has been received for an account that has already been
 * authenticated (i.e. logged-in), and the system is configured to prevent such concurrent access.
 *
 * <p>This is useful when an application must ensure that only one person is logged-in to a single
 * account at any given time.
 *
 * <p>Sometimes account names and passwords are lazily given away
 * to many people for easy access to a system.  Such behavior is undesirable in systems where
 * users are accountable for their actions, such as in government applications, or when licensing
 * agreements must be maintained, such as those which only allow 1 user per paid license.
 *
 * <p>By disallowing concurrent access, such systems can ensure that each authenticated session
 * corresponds to one and only one user at any given time.
 *
 * @since 1.0
 * @author Les Hazlewood
 */
public class ConcurrentAccessException extends AccountException {

    /**
     * Creates a new ConcurrentAccessException.
     */
    public ConcurrentAccessException() {
        super();
    }

    /**
     * Constructs a new ConcurrentAccessException.
     * @param message the reason for the exception
     */
    public ConcurrentAccessException( String message ) {
        super( message );
    }

    /**
     * Constructs a new ConcurrentAccessException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ConcurrentAccessException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new ConcurrentAccessException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ConcurrentAccessException( String message, Throwable cause ) {
        super( message, cause );
    }

}
