/*
 * Copyright (C) 2005 Les Hazlewood
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
package org.jsecurity.util;

import org.jsecurity.JSecurityException;

/**
 * Exception thrown when trying to construct a {@link java.security.Permission Permission} via reflection, and
 * JSecurity can't find a suitable constructor with which to instantiate the Permission class.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class ConstructorAcquisitionException extends JSecurityException {

    public ConstructorAcquisitionException() {
        super();
    }

    public ConstructorAcquisitionException( String message ) {
        super( message );
    }

    public ConstructorAcquisitionException( Throwable cause ) {
        super( cause );
    }

    public ConstructorAcquisitionException( String message, Throwable cause ) {
        super( message, cause );
    }

}
