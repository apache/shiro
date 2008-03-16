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
package org.jsecurity.session.event;

import org.jsecurity.SecurityEvent;

import java.io.Serializable;
import java.text.DateFormat;

/**
 * General event concerning a {@link org.jsecurity.session.Session Session} instance.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class SessionEvent extends SecurityEvent {

    /**
     * Session ID associated with this event.
     */
    protected final Serializable sessionId;

    /**
     * Constructs a new session event associated with the specified session.
     *
     * @param sessionId the session id of the session associated with this event.
     */
    public SessionEvent( Serializable sessionId ) {
        this( sessionId, sessionId );
    }

    /**
     * Constructs a new session event with the given source and session ID.
     *
     * @param source the source of this event.
     * @param sessionId the session ID of the session associated with this event.
     */
    public SessionEvent( Object source, Serializable sessionId ) {
        super( source );
        this.sessionId = sessionId;
    }

    public Serializable getSessionId() {
        return this.sessionId;
    }

    public StringBuffer toStringBuffer() {
        StringBuffer sb = new StringBuffer();
        sb.append("eventClass=").append(getClass().getName());
        sb.append(",source=").append(getSource());
        sb.append(",sessionId=").append(getSessionId());
        sb.append(",timestamp=").append( DateFormat.getInstance().format( getTimestamp() ) );
        return sb;
    }
}
