/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.session;

import org.jsecurity.JSecurityException;

import java.io.Serializable;

/**
 * General security exception attributed to problems during interaction with the system during
 * a session.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SessionException extends JSecurityException {

    private Serializable sessionId;

    /**
     * Creates a new SessionException.
     */
    public SessionException() {
        super();
    }

    /**
     * Constructs a new SessionException.
     * @param message the reason for the exception
     */
    public SessionException( String message ) {
        super( message );
    }

    /**
     * Constructs a new SessionException.
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public SessionException( Throwable cause ) {
        super( cause );
    }

    /**
     * Constructs a new SessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public SessionException( String message, Throwable cause ) {
        super( message, cause );
    }

    /**
     * Constructs a new SessionException.
     * @param sessionId the session id of associated {@link Session Session}.
     */
    public SessionException( Serializable sessionId ) {
        setSessionId( sessionId );
    }

    /**
     * Constructs a new SessionException.
     * @param message the reason for the exception
     * @param sessionId the session id of associated {@link Session Session}.
     */
    public SessionException( String message, Serializable sessionId ) {
        this( message );
        setSessionId( sessionId );
    }

    /**
     * Constructs a new InvalidSessionException.
     * @param message the reason for the exception
     * @param cause the underlying Throwable that caused this exception to be thrown.
     * @param sessionId the session id of associated {@link Session Session}.
     */
    public SessionException( String message, Throwable cause, Serializable sessionId ) {
        this( message, cause );
        setSessionId( sessionId );
    }

    /**
     * Returns the session id of the associated <tt>Session</tt>.
     * @return the session id of the associated <tt>Session</tt>.
     */
    public Serializable getSessionId() {
        return sessionId;
    }

    /**
     * Sets the session id of the <tt>Session</tt> associated with this exception.
     * @param sessionId the session id of the <tt>Session</tt> associated with this exception.
     */
    public void setSessionId( Serializable sessionId ) {
        this.sessionId = sessionId;
    }

}
