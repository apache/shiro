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
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;

import java.io.Serializable;

/**
 * An AbstractCachingSessionDAO is a SessionDAO that provides a transparent caching layer between the components that
 * use it and the underlying EIS (Enterprise Information System) for enhanced performance.
 *
 * <p>This implementation caches all active sessions in a cache created by a required {@link CacheProvider}.  All
 * <tt>SessionDAO</tt> methods are implemented by this class to employ caching behavior and delegates the actual
 * EIS operations to respective do* methods to be implemented by subclasses (doCreate, doRead, etc).
 *
 * <p>After instantiating an instance of this class (or subclass) and setting the <tt>CacheProvider</tt> property,
 * the {@link #init} method must be called to properly initialize the cache.  Also, to ensure proper cache
 * shutdown and cleanup, the {@link #destroy} method must be called when the instance is no longer to be used.
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

    public static final String ACTIVE_SESSION_CACHE_NAME = "jsecurity-activeSessionCache";
    public static final String STOPPED_SESSION_CACHE_NAME = "jsecurity-stoppedSessionCache";

    /**
     * JavaBeans compatible constructor.  The {@link #setCacheProvider CacheProvider} property must be set and the
     * {@link #init} method called before the instance can be used.
     */
    public AbstractCachingSessionDAO(){}

    /**
     * Sets the cacheProvider to use for constructing the session cache.
     * @param cacheProvider the provider to use for constructing the session cache.
     */
    public void setCacheProvider( CacheProvider cacheProvider ) {
        this.cacheProvider = cacheProvider;
    }

    /**
     * <b>For testing only</b> - set this property to <tt>true</tt> only for testing - the default value of
     * <tt>false</tt> should be used in all production environments.
     *
     * <p>If set to <tt>true</tt>, this CachingDAO will cache sessions that have stopped or expired, essentially
     * allowing this DAO to act as a simulated EIS (like the {@link MemorySessionDAO} implementation).  This is very
     * convenient when testing on a local development machine without requiring a database or filesystem to back
     * sessions.
     *
     * <p>The default value is <tt>false</tt> and should remain so for production systems.
     *
     * @param maintainStoppedSessions whether or not to maintain a cache for stopped sessions.
     */
    public void setMaintainStoppedSessions( boolean maintainStoppedSessions) {
        this.maintainStoppedSessions = maintainStoppedSessions;
    }

    /**
     * Constructor taking in the required <tt>CacheProvider</tt> property.  This constructor will call init()
     * automatically, thereby making the instance ready for use immediately after instantiation.
     *
     * @param provider the required <tt>CacheProvider</tt> property necessary for cache initialization.
     */
    public AbstractCachingSessionDAO( CacheProvider provider ) {
        this( provider, false );
    }

    /**
     * Supplementary constructor, primarily used for testing.
     *
     * @param provider the required <tt>CacheProvider</tt> property necessary for cache initialization.
     * @param maintainStoppedSessions whether or not to maintain a cache for stopped sessions - the default is
     * <tt>false</tt> for the reasons mentioned in the {@link #setMaintainStoppedSessions(boolean)} JavaDoc.
     */
    public AbstractCachingSessionDAO( CacheProvider provider, boolean maintainStoppedSessions ) {
        setCacheProvider( provider );
        setMaintainStoppedSessions( maintainStoppedSessions );
        init();
    }

    /**
     * Initializes this DAO's internal session cache.  Subclasses can override the {@link #onInit} method for
     * additional custom startup behavior.
     */
    public void init() {
        if ( this.cacheProvider == null ) {
            throw new IllegalStateException( "CacheProvider property must be set." );
        }

        this.activeSessions = buildActiveSessionCache( this.cacheProvider );
        if ( maintainStoppedSessions ) {
            this.stoppedSessions = buildStoppedSessionCache( this.cacheProvider );
        }

        onInit();
    }

    /**
     * {@link Cache#destroy Destroys} the specified Cache object, catching any exception and logging it to avoid
     * throwing an exception during shutdown.
     * @param cache the Cache to {@link Cache#destroy destroy}.
     */
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
    }

    /**
     * Cleanly releases the internal session cache and performs necessary cleanup.
     */
    public void destroy() {
        destroy( activeSessions );
        destroy( stoppedSessions );
        onDestroy();
    }

    /**
     * Builds a Cache with the given name using the specified CacheProvider.
     *
     * <p>The default implementation merely returns <code>cacheProvider.buildCache( cacheName );</code>.
     *
     * @param cacheProvider the provider to use to build the cache.
     * @param cacheName the name associated with the cache to build.
     * @return a Cache built with the specified name.
     */
    protected Cache buildCache( CacheProvider cacheProvider, String cacheName ) {
        return cacheProvider.buildCache( cacheName );
    }

    /**
     * Creates the <tt>activeSessions</tt> cache class attribute using the specified CacheProvider.
     *
     * @param cacheProvider the provider to use to create the </tt>activeSessions</tt> cache.
     * @return the Cache instance to assign to the <tt>activeSessions</tt> class attribute.
     */
    protected Cache buildActiveSessionCache( CacheProvider cacheProvider ) {
        return buildCache( cacheProvider, ACTIVE_SESSION_CACHE_NAME );
    }

    /**
     * Creates the <tt>stoppedSessions</tt> cache class attribute using the specified CacheProvider.
     *
     * <p>This method should only be called when {@link #setMaintainStoppedSessions(boolean) maintainStoppedSessions} is
     * <tt>true</tt>
     * 
     * @param cacheProvider the provider to use to create the </tt>stoppedSessions</tt> cache.
     * @return the Cache instance to assign to the <tt>stoppedSessions</tt> class attribute.
     */
    protected Cache buildStoppedSessionCache( CacheProvider cacheProvider ) {
        return buildCache( cacheProvider, STOPPED_SESSION_CACHE_NAME );
    }

    /**
     * Template callback methods for subclass custom initialization behavior, so they don't have to override
     * the {@link #init} method.
     */
    protected void onInit(){}

    /**
     * Template callback method for subclass custom destroy behavior, so they don't have to override the
     * {@link #destroy} method.
     */
    protected void onDestroy(){}

    /**
     * Creates the session by delegating EIS creation to subclasses via the {@link #doCreate} method, and then
     * caches the session.
     *
     * @param session Session object to create in the EIS and then cache.
     */
    public Serializable create(Session session) {
        Serializable sessionId = doCreate( session );
        verifySessionId( sessionId );
        activeSessions.put( sessionId, session );
        return sessionId;
    }

    /**
     * Ensures the sessionId returned from the subclass implementation of {@link #doCreate} is not null and not
     * already in use.
     * @param sessionId session id returned from the subclass implementation of {@link #doCreate}
     */
    protected void verifySessionId( Serializable sessionId ) {
        if ( sessionId == null ) {
            String msg = "sessionId returned from doCreate implementation is null.  Please verify the implementation.";
            throw new IllegalStateException( msg );
        }
        ensureUncached( sessionId );
    }

    /**
     * Ensures that there is no cache entry already in place for a session with id of <tt>sessionId</tt>.  Used by
     * the {@link #verifySessionId} implementation.
     * @param sessionId the session id to check for non-existence in the cache.
     */
    protected void ensureUncached( Serializable sessionId ) {
        if ( activeSessions.get( sessionId ) != null ) {
            String msg = "There is an existing session already created with session id [" +
                         sessionId + "].  Session ID's must be unique.";
            throw new IllegalArgumentException( msg );
        }
    }

    /**
     * Subclass hook to actually persist the given <tt>Session</tt> instance to the underlying EIS.
     * @param session the Session instance to persist to the EIS.
     * @return the id of the session created in the EIS (i.e. this is almost always a primary key and should be the
     * value returned from {@link org.jsecurity.session.Session#getSessionId() Session.getSessionId()}.
     */
    protected abstract Serializable doCreate( Session session );

    /**
     * Retrieves the Session object from the underlying EIS identified by <tt>sessionId</tt>.
     *
     * <p>Upon receiving the Session object from the subclass's {@link #doReadSession} implementation, it will be
     * cached first and then returned to the caller.
     *
     * @param sessionId the id of the session to retrieve from the EIS.
     * @return the session identified by <tt>sessionId</tt> in the EIS.
     * @throws UnknownSessionException if the id specified does not correspond to any session in the cache or EIS.
     */
    public Session readSession(Serializable sessionId) throws UnknownSessionException {
        Session s = (Session)activeSessions.get( sessionId );
        if ( s == null ) {
            if ( stoppedSessions != null ) {
                s = (Session)stoppedSessions.get( sessionId );
            }
            if ( s == null ) {
                s = doReadSession( sessionId );
                if ( s != null ) {
                    if ( s.getStopTimestamp() != null || s.isExpired() ) {
                        if ( stoppedSessions != null ) {
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

    /**
     * Subclass implmentation hook to actually retrieve the Session object from the underlying EIS.
     *
     * @param sessionId the id of the <tt>Session</tt> to retrieve.
     * @return the Session in the EIS identified by <tt>sessionId</tt>
     */
    protected abstract Session doReadSession( Serializable sessionId );

    /**
     * Updates the state of the given session to the EIS.
     *
     * <p>If the specified session was previously cached, and the session is now
     * {@link org.jsecurity.session.Session#getStopTimestamp() stopped} or
     * {@link org.jsecurity.session.Session#isExpired() expired}, it will be removed from the cache.
     *
     * <p>If the specified session is not stopped or expired, and was not yet in the cache, it will be added to the
     * cache.
     *
     * <p>Finally, this method calls {@link #doUpdate} for the subclass to actually push the object state to the EIS.
     *
     * @param session the session object to update in the EIS.
     * @throws UnknownSessionException if no existing EIS session record exists with the
     * identifier of {@link Session#getSessionId() session.getSessionId()}
     */
    public void update( Session session ) throws UnknownSessionException {
        Serializable id = session.getSessionId();
        if ( (session.getStopTimestamp() != null) || session.isExpired() ) {
            activeSessions.remove( id );
            if ( stoppedSessions != null ) {
                stoppedSessions.put( id, session );
            }
        } else {
            if ( activeSessions.get( id ) == null ) {
                activeSessions.put( id, session );
            }
        }
        doUpdate( session );
    }

    /**
     * Subclass implementation hook to actually persist the <tt>Session</tt>'s state to the underlying EIS.
     * @param session the session object whose state will be propagated to the EIS.
     */
    protected abstract void doUpdate( Session session );

    /**
     * Removes the specified session from any cache and then permanently deletes the session from the EIS by
     * delegating to {@link #doDelete}.
     * @param session the session to remove from caches and permanently delete from the EIS.
     */
    public void delete(Session session) {
        Serializable id = session.getSessionId();
        activeSessions.remove( id );
        if ( stoppedSessions != null ) {
            stoppedSessions.remove( id );
        }
        doDelete( session );
    }

    /**
     * Subclass implementation hook to permanently delete the given Session from the underlying EIS.
     * @param session the session instance to permanently delete from the EIS.
     */
    protected abstract void doDelete( Session session );

    /**
     * Returns the total number of sessions that are active (i.e. those that are not stopped or expired).
     *
     * <p>This implementation merely returns the size of the internal <tt>activeSessions</tt> cache.  Subclass
     * implementations may wish to override this method to get the number in a different way - perhaps from a
     * RDBMS query or other means.
     * @return the number of sessions in the system that are currently active (i.e. not stopped or expired).
     */
    public long getActiveSessionCount() {
        return activeSessions.getElementCount();
    }
}
