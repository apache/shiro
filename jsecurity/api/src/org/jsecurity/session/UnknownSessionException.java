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
package org.jsecurity.session;

import java.io.Serializable;

/**
 * Exception thrown when attempting to interact with the system under the pretense of a
 * particular session (e.g. under a specific session id), and that session does not exist in
 * the system.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class UnknownSessionException extends InvalidSessionException {

    /**
     * Creates a new UnknownSessionException.
     */
    public UnknownSessionException() {
        super();
    }

    /**
     * Constructs a new UnknownSessionException.
     * @param message the reason for the exception
     */
    public UnknownSessionException( String message ) {
        super( message );
    }

    /**
     * Constructs a new UnknownSessionException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnknownSessionException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new UnknownSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public UnknownSessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    /**
     * Constructs a new UnknownSessionException.
     * @param sessionId the session id given that is unknown to the system.
     */
    public UnknownSessionException( Serializable sessionId ) {
        super( sessionId );
    }

    /**
     * Constructs a new UnknownSessionException.
     * @param message the reason for the exception
     * @param sessionId the session id given that is unknown to the system.
     */
    public UnknownSessionException( String message, Serializable sessionId ) {
        super( message, sessionId );
    }

    /**
     * Constructs a new UnknownSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     * @param sessionId the session id given that is unknown to the system.
     */
    public UnknownSessionException( String message, Throwable cause, Serializable sessionId ) {
        super( message, cause, sessionId );
    }
}
