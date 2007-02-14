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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.session.Session;
import org.jsecurity.session.UnknownSessionException;
import org.jsecurity.session.support.eis.SessionDAO;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.Destroyable;

import java.io.Serializable;

/**
 * TODO - JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class AbstractCachingSessionDAO implements SessionDAO, Initializable, Destroyable {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected Cache activeSessions = null;
    protected Cache stoppedSessions = null;

    protected CacheProvider cacheProvider = null;
    protected boolean maintainStoppedSessions = false;

    protected static final String ACTIVE_SESSIONS_CACHE_NAME = "jsecurity-activeSessionCache";
    protected static final String STOPPED_SESSIONS_CACHE_NAME = "jsecurity-stoppedSessionsCache";

    public AbstractCachingSessionDAO(){}

    public void setCacheProvider( CacheProvider cacheProvider ) {
        this.cacheProvider = cacheProvider;
    }

    public void setMaintainStoppedSessions( boolean maintainStoppedSessions) {
        this.maintainStoppedSessions = maintainStoppedSessions;
    }

    public AbstractCachingSessionDAO( CacheProvider provider ) {
        this( provider, false );
    }

    public AbstractCachingSessionDAO( CacheProvider provider, boolean maintainStoppedSessions ) {
        setCacheProvider( provider );
        setMaintainStoppedSessions( maintainStoppedSessions );
        init();
    }

    public void init() {
        if ( this.cacheProvider == null ) {
            throw new IllegalStateException( "CacheProvider property must be set." );
        }

        this.activeSessions = buildActiveSessionsCache( this.cacheProvider );
        if ( maintainStoppedSessions ) {
            this.stoppedSessions = buildStoppedSessionsCache( this.cacheProvider );
        }

        onInit();
    }

    protected void destroy( Cache cache ) {
        try {
            if ( cache != null ) {
                cache.destroy();
            }
        } catch (Exception e) {
            if ( log.isWarnEnabled() ) {
                log.warn( "Unable to cleanly destroy cache [" + cache + "]." );
            }
        }
        onDestroy();
    }

    public void destroy() {
        destroy( activeSessions );
        destroy( stoppedSessions );
    }

    protected Cache buildCache( CacheProvider cacheProvider, String cacheName ) {
        return cacheProvider.buildCache( cacheName );
    }
    protected Cache buildActiveSessionsCache( CacheProvider cacheProvider ) {
        return buildCache( cacheProvider, ACTIVE_SESSIONS_CACHE_NAME );
    }

    protected Cache buildStoppedSessionsCache( CacheProvider cacheProvider ) {
        return buildCache( cacheProvider, STOPPED_SESSIONS_CACHE_NAME );   
    }

    protected void onInit(){}

    protected void onDestroy(){}

    public void create(Session session) {
        Serializable sessionId = doCreate( session );
        verifySessionId( sessionId );
        activeSessions.put( sessionId, session );
    }

    protected void verifySessionId( Serializable sessionId ) {
        if ( sessionId == null ) {
            String msg = "sessionId returned from doCreate implementation is null.  Please verify the implementation.";
            throw new IllegalStateException( msg );
        }
        ensureUncached( sessionId );
    }

    protected void ensureUncached( Serializable sessionId ) {
        if ( activeSessions.get( sessionId ) != null ) {
            String msg = "There is an existing session already created with session id [" +
                         sessionId + "].  Session ID's must be unique.";
            throw new IllegalArgumentException( msg );
        }
    }

    protected abstract Serializable doCreate( Session session );

    public Session readSession(Serializable sessionId) throws UnknownSessionException {
        Session s = (Session)activeSessions.get( sessionId );
        if ( s == null ) {
            if ( maintainStoppedSessions ) {
                s = (Session)stoppedSessions.get( sessionId );
            }
            if ( s == null ) {
                s = doReadSession( sessionId );
                if ( s != null ) {
                    if ( s.getStopTimestamp() != null || s.isExpired() ) {
                        if ( maintainStoppedSessions ) {
                            stoppedSessions.put( sessionId, s );
                        }
                    } else {
                        activeSessions.put( sessionId, s );
                    }
                }
            }
        }
        if ( s == null ) {
            throw new UnknownSessionException( "There is no session with id [" + sessionId + "]" );
        }
        return s;
    }

    protected abstract Session doReadSession( Serializable sessionId );

    public void update( Session session ) throws UnknownSessionException {
        Serializable id = session.getSessionId();
        if ( (session.getStopTimestamp() != null) || session.isExpired() ) {
            activeSessions.remove( id );
            if ( maintainStoppedSessions ) {
                stoppedSessions.put( id, session );
            }
        } else {
            if ( activeSessions.get( id ) == null ) {
                activeSessions.put( id, session );
            }
        }
        doUpdate( session );
    }
    protected abstract void doUpdate( Session session );

    public void delete(Session session) {
        Serializable id = session.getSessionId();
        activeSessions.remove( id );
        stoppedSessions.remove( id );
        doDelete( session );
    }

    protected abstract void doDelete( Session session );

    public int getActiveSessionCount() {
        return ( new Long( activeSessions.getElementCount() ) ).intValue();
    }
}
