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

package org.jsecurity.session.support.eis.support;

import org.jsecurity.cache.support.HashtableCacheProvider;
import org.jsecurity.session.Session;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;

/**
 * Simple memory-based implementation of the SessionDAO.  It does not save session data to disk, so
 * this implementation is not recommended in production-quality recoverable environments
 * (i.e. those needing session state restored when a server restarts).
 *
 * <p>If you need session recovery in the event of a server failure or restart, consider using
 * a file-based or RDBMS-based implementation.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class MemorySessionDAO extends AbstractCachingSessionDAO {

    public MemorySessionDAO() {
        setCacheProvider( new HashtableCacheProvider() );
        setMaintainStoppedSessions( true );
    }


    protected Serializable doCreate(Session session) {
        //no need to do anything with the session - parent class persists to in-memory cache already.  Just return id:
        return session.getSessionId();
    }

    protected Session doReadSession( Serializable sessionId ) {
        return null; //should never execute because this implementation relies on parent class to access cache, which
                     //is where all in-memory sessions reside.
    }

    protected void doUpdate(Session session) {
        //does nothing - parent class persists to in-memory cache.
    }

    protected void doDelete(Session session) {
        //does nothing - parent class removes from in-memory cache.
    }

    public Collection<Session> getActiveSessions() {
        return Collections.unmodifiableCollection( activeSessions.toMap().values() );
    }
}
