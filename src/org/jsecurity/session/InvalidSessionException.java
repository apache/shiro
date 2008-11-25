/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jsecurity.session;

import java.io.Serializable;

/**
 * Exception thrown when attempting to interact with the system under an established session
 * when that session is considered invalid.  The meaning of the term 'invalid' is based on
 * application behavior.  For example, a Session is considered invalid if it has been explicitly
 * stopped (e.g. when a user logs-out or when explicitly
 * {@link org.jsecurity.session.Session#stop() stopped} programmatically.  A Session can also be
 * considered invalid if it has expired.
 *
 * @author Les Hazlewood
 * @see StoppedSessionException
 * @see ExpiredSessionException
 * @see UnknownSessionException
 * @since 0.1
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
     *
     * @param message the reason for the exception
     */
    public InvalidSessionException(String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param cause the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSessionException(Throwable cause) {
        super(cause);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public InvalidSessionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param sessionId the session id of the session that has been invalidated.
     */
    public InvalidSessionException(Serializable sessionId) {
        this("Session with id [" + sessionId + "] has been invalidated (stopped)", sessionId);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param message   the reason for the exception
     * @param sessionId the session id of the session that has been invalidated.
     */
    public InvalidSessionException(String message, Serializable sessionId) {
        super(message, sessionId);
    }

    /**
     * Constructs a new InvalidSessionException.
     *
     * @param message   the reason for the exception
     * @param cause     the underlying Throwable that caused this exception to be thrown.
     * @param sessionId the session id of the session that has been invalidated.
     */
    public InvalidSessionException(String message, Throwable cause, Serializable sessionId) {
        super(message, cause, sessionId);
    }

}
