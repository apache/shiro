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
package org.jsecurity.subject;

/**
 * Exception thrown when a <tt>Subject</tt> is accessed that has been invalidated.  Usually this occurs
 * when accessing a <tt>Subject</tt> whose {@link Subject#logout()} method
 * has been called.  
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class InvalidSubjectException extends SubjectException {

    public InvalidSubjectException() {
        super();
    }

    public InvalidSubjectException( String message ) {
        super( message );
    }

    public InvalidSubjectException( Throwable cause ) {
        super( cause );
    }

    public InvalidSubjectException( String message, Throwable cause ) {
        super( message, cause );
    }
}
