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
 * Thrown when a system is configured to only allow a certain number of authentication attempts
 * over a period of time and the current session has failed to authenticate successfully within
 * that number.  The resulting action of such an exception is applicaiton dependent, but
 * most systems either temporarily or permanently lock that account to prevent further
 * attempts.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class ExcessiveAttemptsException extends AccountException {

    public ExcessiveAttemptsException() {
        super();
    }

    public ExcessiveAttemptsException( String message ) {
        super( message );
    }

    public ExcessiveAttemptsException( Throwable cause ) {
        super( cause );
    }

    public ExcessiveAttemptsException( String message, Throwable cause ) {
        super( message, cause );
    }
}
