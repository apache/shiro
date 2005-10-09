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
package org.jsecurity;

import java.io.Serializable;

/**
 * Root exception for all JSecurity runtime exceptions.  This class is used as the root instead
 * of {@link java.lang.SecurityException} to remove the potential for conflicts;  many other
 * frameworks and products (such as J2EE containers) perform special operations when
 * encountering {@link java.lang.SecurityException}.
 *
 * @since 1.0
 * @author Les Hazlewood
 */
public class JSecurityException extends RuntimeException implements Serializable {

    /**
     * Creates a new JSecurityException.
     */
    public JSecurityException() {
        super();
    }

    /**
     * Constructs a new JSecurityException.
     * @param message the reason for the exception
     */
    public JSecurityException( String message ) {
        super( message );
    }

    /**
     * Constructs a new JSecurityException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public JSecurityException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new JSecurityException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public JSecurityException( String message, Throwable cause ) {
        super( message, cause );
    }

}
