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
 * Thrown during the authentication process when the system determines the submitted credential
 * has expired and will not allow login.
 *
 * <p>This is most often used to alert a user that their credential (e.g. password or
 * cryptography key) has expired and they should change its value.  In such systems, the component
 * invoking the authentication might catch this exception and redirect the user to an appropriate
 * view to allow them to update their password.
 *
 * @author Les Hazlewood 
 */
public class ExpiredCredentialException extends CredentialException {

    public ExpiredCredentialException() {
        super();
    }

    public ExpiredCredentialException( String message ) {
        super( message );
    }

    public ExpiredCredentialException( Throwable cause ) {
        super( cause );
    }

    public ExpiredCredentialException( String message, Throwable cause ) {
        super( message, cause );
    }
}
