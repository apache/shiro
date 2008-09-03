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
package org.jsecurity.session.mgt.eis;

import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.session.Session;
import org.jsecurity.session.UnknownSessionException;
import org.jsecurity.session.mgt.ValidatingSession;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;

/**
 * An CachingSessionDAO is a SessionDAO that provides a transparent caching layer between the components that
 * use it and the underlying EIS (Enterprise Information System) for enhanced performance.
 *
 * <p>This implementation caches all active sessions in a cache created by a
 * {@link org.jsecurity.cache.CacheManager}.  All <tt>SessionDAO</tt> methods are implemented by this class to employ
 * caching behavior and delegates the actual EIS operations to respective do* methods to be implemented by
 * subclasses (doCreate, doRead, etc).
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public abstract class CachingSessionDAO implements SessionDAO, CacheManagerAware {

    public static final String ACTIVE_SESSION_CACHE_NAME = "jsecurity-activeSessionCache";

    private CacheManager cacheManager;
    private Cache activeSessions;
    private String activeSessionsCacheName = ACTIVE_SESSION_CACHE_NAME;

    /**
     * JavaBeans compatible constructor.
     */
    public CachingSessionDAO() {
    }

    /**
     * Sets the cacheManager to use for constructing the session cache.
     *
     * @param cacheManager the manager to use for constructing the session cache.
     */
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        //force cache reload:
        this.activeSessions = null;
    }

    /**
     * Returns the CacheManager used by the implementation that creates the activeSessions Cache.
     *
     * @return the CacheManager used by the implementation that creates the activeSessions Cache.
     */
    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public String getActiveSessionsCacheName() {
        return activeSessionsCacheName;
    }

    public void setActiveSessionsCacheName(String activeSessionsCacheName) {
        this.activeSessionsCacheName = activeSessionsCacheName;
    }

    public Cache getActiveSessionsCache() {
        return this.activeSessions;
    }

    protected Cache getActiveSessionsCacheLazy() {
        if (this.activeSessions == null) {
            this.activeSessions = createActiveSessionsCache();
        }
        return this.activeSessions;
    }

    public void setActiveSessionsCache(Cache cache) {
        this.activeSessions = cache;
    }

    protected Cache createActiveSessionsCache() {
        Cache cache = null;
        CacheManager mgr = getCacheManager();
        if (mgr != null) {
            String name = getActiveSessionsCacheName();
            cache = mgr.getCache(name);
        }
        return cache;
    }

    /**
     * Creates the session by delegating EIS creation to subclasses via the {@link #doCreate} method, and then
     * caches the session.
     *
     * @param session Session object to create in the EIS and then cache.
     */
    public Serializable create(Session session) {
        Serializable sessionId = doCreate(session);
        verifySessionId(sessionId);
        cacheValidSession(session, sessionId);
        return sessionId;
    }

    protected Session getCachedSession(Serializable sessionId) {
        Session cached = null;
        if (sessionId != null) {
            Cache cache = getActiveSessionsCacheLazy();
            if (cache != null) {
                cached = getCachedSession(sessionId, cache);
            }
        }
        return cached;
    }

    protected Session getCachedSession(Serializable sessionId, Cache cache) {
        return (Session) cache.get(sessionId);
    }

    protected void cacheValidSession(Session session, Serializable sessionId) {
        if (session == null || sessionId == null) {
            return;
        }

        Cache cache = getActiveSessionsCacheLazy();
        if (cache == null) {
            return;
        }

        if (session instanceof ValidatingSession && !((ValidatingSession) session).isValid()) {
            uncache(session);
        } else {
            cache(session, sessionId, cache);
        }
    }

    protected void cache(Session session, Serializable sessionId, Cache cache) {
        cache.put(sessionId, session);
    }

    /**
     * Ensures the sessionId returned from the subclass implementation of {@link #doCreate} is not null and not
     * already in use.
     *
     * @param sessionId session id returned from the subclass implementation of {@link #doCreate}
     */
    protected void verifySessionId(Serializable sessionId) {
        if (sessionId == null) {
            String msg = "sessionId returned from doCreate implementation is null.  Please verify the implementation.";
            throw new IllegalStateException(msg);
        }
        ensureUncached(sessionId);
    }

    /**
     * Ensures that there is no cache entry already in place for a session with id of <tt>sessionId</tt>.  Used by
     * the {@link #verifySessionId} implementation.
     *
     * @param sessionId the session id to check for non-existence in the cache.
     */
    protected void ensureUncached(Serializable sessionId) {
        Cache cache = getActiveSessionsCacheLazy();
        if (cache != null && cache.get(sessionId) != null) {
            String msg = "There is an existing session already created with session id [" +
                    sessionId + "].  Session ID's must be unique.";
            throw new IllegalArgumentException(msg);
        }
    }

    /**
     * Subclass hook to actually persist the given <tt>Session</tt> instance to the underlying EIS.
     *
     * @param session the Session instance to persist to the EIS.
     * @return the id of the session created in the EIS (i.e. this is almost always a primary key and should be the
     *         value returned from {@link org.jsecurity.session.Session#getId() Session.getId()}.
     */
    protected abstract Serializable doCreate(Session session);

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

        Session s = getCachedSession(sessionId);

        if (s == null) {
            s = doReadSession(sessionId);
            if (s != null) {
                cacheValidSession(s, sessionId);
            }
        }

        if (s == null) {
            throw new UnknownSessionException("There is no session with id [" + sessionId + "]");
        }
        return s;
    }

    /**
     * Subclass implmentation hook to actually retrieve the Session object from the underlying EIS.
     *
     * @param sessionId the id of the <tt>Session</tt> to retrieve.
     * @return the Session in the EIS identified by <tt>sessionId</tt>
     */
    protected abstract Session doReadSession(Serializable sessionId);

    /**
     * Updates the state of the given session to the EIS.
     *
     * <p>If the specified session was previously cached, and the session is now invalid,
     * it will be removed from the cache.
     *
     * <p>If the specified session is not stopped or expired, and was not yet in the cache, it will be added to the
     * cache.
     *
     * <p>Finally, this method calls {@link #doUpdate} for the subclass to actually push the object state to the EIS.
     *
     * @param session the session object to update in the EIS.
     * @throws UnknownSessionException if no existing EIS session record exists with the
     *                                 identifier of {@link Session#getId() session.getId()}
     */
    public void update(Session session) throws UnknownSessionException {
        doUpdate(session);
        cacheValidSession(session, session.getId());
    }

    /**
     * Subclass implementation hook to actually persist the <tt>Session</tt>'s state to the underlying EIS.
     *
     * @param session the session object whose state will be propagated to the EIS.
     */
    protected abstract void doUpdate(Session session);

    /**
     * Removes the specified session from any cache and then permanently deletes the session from the EIS by
     * delegating to {@link #doDelete}.
     *
     * @param session the session to remove from caches and permanently delete from the EIS.
     */
    public void delete(Session session) {
        doDelete(session);
        uncache(session);
    }

    /**
     * Subclass implementation hook to permanently delete the given Session from the underlying EIS.
     *
     * @param session the session instance to permanently delete from the EIS.
     */
    protected abstract void doDelete(Session session);

    protected void uncache(Session session) {
        if (session == null) {
            return;
        }
        Serializable id = session.getId();
        if (id == null) {
            return;
        }
        Cache cache = getActiveSessionsCacheLazy();
        if (cache != null) {
            cache.remove(id);
        }
    }

    /**
     * Returns all active sessions in the system.
     *
     * <p>This implementation merely returns the sessions found in the activeSessions cache.  Subclass implementations
     * may wish to override this method to retrieve them in a different way, perhaps by an RDBMS query or by other
     * means.
     *
     * @return the sessions found in the activeSessions cache.
     */
    @SuppressWarnings({"unchecked"})
    public Collection<Session> getActiveSessions() {
        Cache cache = getActiveSessionsCacheLazy();
        if (cache != null) {
            return cache.values();
        } else {
            return Collections.EMPTY_LIST;
        }
    }
}
