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
package org.jsecurity.authc.support;

import org.jsecurity.authc.AuthenticationException;

/**
 * Exception thrown during the authentication process when an
 * {@link org.jsecurity.authc.AuthenticationToken AuthenticationToken} implementation is encountered that is not
 * supported by one or more configured {@link org.jsecurity.realm.Realm Realm}s.
 *
 * @see ModularAuthenticationStrategy
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class UnsupportedTokenException extends AuthenticationException {

    /**
     * Creates a new UnsupportedTokenException.
     */
    public UnsupportedTokenException() {
        super();
    }

    /**
     * Constructs a new UnsupportedTokenException.
     * @param message the reason for the exception
     */
    public UnsupportedTokenException( String message ) {
        super( message );
    }

    /**
     * Constructs a new UnsupportedTokenException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnsupportedTokenException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new UnsupportedTokenException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnsupportedTokenException( String message, Throwable cause ) {
        super( message, cause );
    }
}
