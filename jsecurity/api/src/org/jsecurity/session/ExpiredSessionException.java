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
package org.jsecurity.session;

import java.io.Serializable;

/**
 * A special case of a StoppedSessionException.  An expired session is a session that has
 * stopped explicitly due to inactivity (i.e. time-out), as opposed to stopping due to log-out or
 * other reason.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class ExpiredSessionException extends StoppedSessionException {

    /**
     * Creates a new ExpiredSessionException.
     */
    public ExpiredSessionException() {
        super();
    }

    /**
     * Constructs a new ExpiredSessionException.
     * @param message the reason for the exception
     */
    public ExpiredSessionException( String message ) {
        super( message );
    }

    /**
     * Constructs a new ExpiredSessionException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredSessionException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new ExpiredSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public ExpiredSessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    /**
     * Constructs a new ExpiredSessionException.
     * @param sessionId the session id of the session that expired.
     */
    public ExpiredSessionException( Serializable sessionId ) {
        this( "Session with id [" + sessionId + "] has expired", sessionId );
    }

    /**
     * Constructs a new ExpiredSessionException.
     * @param message the reason for the exception
     * @param sessionId the session id of the session that expired.
     */
    public ExpiredSessionException( String message, Serializable sessionId ) {
        super( message, sessionId );
    }

    /**
     * Constructs a new ExpiredSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     * @param sessionId the session id of the session that expired.
     */
    public ExpiredSessionException( String message, Throwable cause, Serializable sessionId ) {
        super( message, cause, sessionId );
    }
}
