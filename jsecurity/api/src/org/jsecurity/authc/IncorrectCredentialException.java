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
 * Thrown when attempting to authenticate with a credential that does not match the actual
 * credential associated with the account principal.
 *
 * <p>For example, this exception might be thrown if a user's password is &quot;secret&quot; and
 * &quot;secrets&quot; was entered by mistake.
 *
 * <p>Whether or not an application wishes to let
 * the user know if they entered in an incorrect credential is at the discretion of those
 * responsible for defining the view and what happens when this exception occurs.
 *
 * @author Les Hazlewood
 */
public class IncorrectCredentialException extends CredentialException {

    public IncorrectCredentialException() {
        super();
    }

    public IncorrectCredentialException( String message ) {
        super( message );
    }

    public IncorrectCredentialException( Throwable cause ) {
        super( cause );
    }

    public IncorrectCredentialException( String message, Throwable cause ) {
        super( message, cause );
    }

}
