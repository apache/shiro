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
 * Exception thrown when attempting to interact with the system under a session that has been
 * stopped.  A session may be stopped in any number of ways, most commonly due to explicit
 * stopping (e.g. from logging out), or due to expiration.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class StoppedSessionException extends InvalidSessionException {

    /**
     * Creates a new StoppedSessionException.
     */
    public StoppedSessionException() {
        super();
    }

    /**
     * Constructs a new StoppedSessionException.
     * @param message the reason for the exception
     */
    public StoppedSessionException( String message ) {
        super( message );
    }

    /**
     * Constructs a new StoppedSessionException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public StoppedSessionException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new StoppedSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public StoppedSessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    /**
     * Constructs a new StoppedSessionException.
     * @param sessionId the session id of the session that has been stopped.
     */
    public StoppedSessionException( Serializable sessionId ) {
        super( sessionId );
    }

    /**
     * Constructs a new StoppedSessionException.
     * @param message the reason for the exception
     * @param sessionId the session id of the session that has been stopped.
     */
    public StoppedSessionException( String message, Serializable sessionId ) {
        super( message, sessionId );
    }

    /**
     * Constructs a new StoppedSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     * @param sessionId the session id of the session that has been stopped.
     */
    public StoppedSessionException( String message, Throwable cause, Serializable sessionId ) {
        super( message, cause, sessionId );
    }

}
