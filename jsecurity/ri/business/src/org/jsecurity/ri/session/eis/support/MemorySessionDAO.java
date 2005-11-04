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

package org.jsecurity.ri.session.eis.support;

import org.jsecurity.ri.session.SimpleSession;
import org.jsecurity.ri.session.eis.SessionDAO;
import org.jsecurity.session.Session;
import org.jsecurity.session.UnknownSessionException;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Simple memory-based implementation of the SessionDAO.  It does not save session data to disk, so
 * this implementation is not recommended in recoverable environments (i.e. those needing
 * session state restored when a server restarts).
 *
 * <p>If you need session recovery in the event of a server failure or restart, consider using
 * a file-based or relational database-based implementation.
 *
 * @author Les Hazlewood
 */
public class MemorySessionDAO implements SessionDAO {

    private final Map<Serializable, Session> activeSessions = new HashMap<Serializable, Session>();
    private final Map<Serializable, Session> stoppedSessions = new HashMap<Serializable, Session>();

    protected void assignId( Session session ) {
        if ( session instanceof SimpleSession ) {
            ( (SimpleSession)session ).setSessionId( UUID.randomUUID() );
        }
    }

    public void create( Session session ) {
        assignId( session );
        Serializable id = session.getSessionId();
        if ( id == null ) {
            String msg = "session must be assigned an id.  Please check assignId( Session s ) " +
                         "implementation.";
            throw new IllegalStateException( msg );
        }

        if ( activeSessions.containsKey( id ) || stoppedSessions.containsKey( id ) ) {
            String msg = "There is an existing session already created with session id [" +
                         id + "].  Session Id's must be unique.";
            throw new IllegalArgumentException( msg );
        }

        synchronized ( activeSessions ) {
            activeSessions.put( id, session );
        }
    }

    public Session readSession( Serializable sessionId ) throws UnknownSessionException {
        Session s = activeSessions.get( sessionId );
        if ( s == null ) {
            s = stoppedSessions.get( sessionId );
        }
        if ( s == null ) {
            String msg = "There is no session with id [" + sessionId + "].";
            throw new UnknownSessionException( msg );
        }
        return s;
    }

    public void update( Session session ) throws UnknownSessionException {
        Serializable id = session.getSessionId();
        //verify the session exists:
        Session s = readSession( id );
        if ( (s.getStopTimestamp() != null) || s.isExpired() ) {
            synchronized ( activeSessions ) {
                activeSessions.remove( id );
            }
            synchronized ( stoppedSessions ) {
                stoppedSessions.put( id, session );
            }
        }
    }

    public void delete( Session session ) {
        Serializable id = session.getSessionId();
        readSession( id ); //verify it exists
        //delete it:
        synchronized ( activeSessions ) {
            activeSessions.remove( id );
        }
        synchronized ( stoppedSessions ) {
            stoppedSessions.remove( id );
        }
    }

    public Collection<Session> getActiveSessions() {
        return activeSessions.values();
    }

    public int getActiveSessionCount() {
        return getActiveSessions().size();
    }

}
