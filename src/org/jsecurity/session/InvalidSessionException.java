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
package org.jsecurity.session;

import java.io.Serializable;

/**
 * Exception thrown when attempting to interact with the system under an established session
 * when that session is considered invalid.  The meaning of the term 'invalid' is based on
 * application behavior.  For example, a Session is considered invalid if it has been explicitly
 * stopped (e.g. in the event of a user log-out or when explicitly
 * {@link org.jsecurity.session.Session#stop() stopped} programmatically.  A Session can also be
 * considered invalid if it has expired.
 *
 * @see StoppedSessionException
 * @see ExpiredSessionException
 * @see UnknownSessionException
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class InvalidSessionException extends SessionException {

    /**
     * Creates a new InvalidSessionException.
     */
    public InvalidSessionException() {
        super();
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param message the reason for the exception
     */
    public InvalidSessionException( String message ) {
        super( message );
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSessionException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param sessionId the session id of the session that has been invalidated.
     */
    public InvalidSessionException( Serializable sessionId ) {
        this( "Session with id [" + sessionId + "] has been invalidated (stopped)", sessionId );
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param message the reason for the exception
     * @param sessionId the session id of the session that has been invalidated.
     */
    public InvalidSessionException( String message, Serializable sessionId ) {
        super( message, sessionId );
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     * @param sessionId the session id of the session that has been invalidated.
     */
    public InvalidSessionException( String message, Throwable cause, Serializable sessionId ) {
        super( message, cause, sessionId );
    }

}
