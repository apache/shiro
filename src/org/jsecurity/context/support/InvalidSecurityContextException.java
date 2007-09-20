/*
 * Copyright (C) 2005-2007 Jeremy Haile
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
package org.jsecurity.context.support;

import org.jsecurity.context.SecurityContextException;

/**
 * Exception thrown when a <tt>SecurityContext</tt> is accessed that has been invalidated.  Usually this occurs
 * when accessing a <tt>SecurityContext</tt> whose {@link org.jsecurity.context.SecurityContext#invalidate()} method
 * has been called.  
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class InvalidSecurityContextException extends SecurityContextException {

    public InvalidSecurityContextException() {
        super();
    }

    public InvalidSecurityContextException( String message ) {
        super( message );
    }

    public InvalidSecurityContextException( Throwable cause ) {
        super( cause );
    }

    public InvalidSecurityContextException( String message, Throwable cause ) {
        super( message, cause );
    }
}
