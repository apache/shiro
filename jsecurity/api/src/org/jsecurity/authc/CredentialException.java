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
 * Exception thrown due to a problem with the credential(s) submitted for an
 * account during the authentication process.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class CredentialException extends AuthenticationException {

    /**
     * Creates a new CredentialException.
     */
    public CredentialException() {
        super();
    }

    /**
     * Constructs a new CredentialException.
     * @param message the reason for the exception
     */
    public CredentialException( String message ) {
        super( message );
    }

    /**
     * Constructs a new CredentialException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public CredentialException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new CredentialException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public CredentialException( String message, Throwable cause ) {
        super( message, cause );
    }

}
