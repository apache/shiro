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
package org.apache.shiro.session.mgt.eis;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.CacheManagerAware;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.UnknownSessionException;
import org.apache.shiro.session.mgt.ValidatingSession;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;

/**
 * An CachingSessionDAO is a SessionDAO that provides a transparent caching layer between the components that
 * use it and the underlying EIS (Enterprise Information System) session backing store (for example, filesystem,
 * database, enterprise grid/cloud, etc).
 * <p/>
 * This implementation caches all active sessions in a configured
 * {@link #getActiveSessionsCache() activeSessionsCache}.  This property is {@code null} by default and if one is
 * not explicitly set, a {@link #setCacheManager cacheManager} is expected to be configured which will in turn be used
 * to acquire the {@code Cache} instance to use for the {@code activeSessionsCache}.
 * <p/>
 * All {@code SessionDAO} methods are implemented by this class to employ
 * caching behavior and delegates the actual EIS operations to respective do* methods to be implemented by
 * subclasses (doCreate, doRead, etc).
 *
 * @since 0.2
 */
public abstract class CachingSessionDAO extends AbstractSessionDAO implements CacheManagerAware {

    /**
     * The default active sessions cache name, equal to {@code shiro-activeSessionCache}.
     */
    public static final String ACTIVE_SESSION_CACHE_NAME = "shiro-activeSessionCache";

    /**
     * The CacheManager to use to acquire the Session cache.
     */
    private CacheManager cacheManager;

    /**
     * The Cache instance responsible for caching Sessions.
     */
    private Cache<Serializable, Session> activeSessions;

    /**
     * The name of the session cache, defaults to {@link #ACTIVE_SESSION_CACHE_NAME}.
     */
    private String activeSessionsCacheName = ACTIVE_SESSION_CACHE_NAME;

    /**
     * Default no-arg constructor.
     */
    public CachingSessionDAO() {
    }

    /**
     * Sets the cacheManager to use for acquiring the {@link #getActiveSessionsCache() activeSessionsCache} if
     * one is not configured.
     *
     * @param cacheManager the manager to use for constructing the session cache.
     */
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    /**
     * Returns the CacheManager to use for acquiring the {@link #getActiveSessionsCache() activeSessionsCache} if
     * one is not configured.  That is, the {@code CacheManager} will only be used if the
     * {@link #getActiveSessionsCache() activeSessionsCache} property is {@code null}.
     *
     * @return the CacheManager used by the implementation that creates the activeSessions Cache.
     */
    public CacheManager getCacheManager() {
        return cacheManager;
    }

    /**
     * Returns the name of the actives sessions cache to be returned by the {@code CacheManager}.  Unless
     * overridden by {@link #setActiveSessionsCacheName(String)}, defaults to {@link #ACTIVE_SESSION_CACHE_NAME}.
     *
     * @return the name of the active sessions cache.
     */
    public String getActiveSessionsCacheName() {
        return activeSessionsCacheName;
    }

    /**
     * Sets the name of the active sessions cache to be returned by the {@code CacheManager}.  Defaults to
     * {@link #ACTIVE_SESSION_CACHE_NAME}.
     *
     * @param activeSessionsCacheName the name of the active sessions cache to be returned by the {@code CacheManager}.
     */
    public void setActiveSessionsCacheName(String activeSessionsCacheName) {
        this.activeSessionsCacheName = activeSessionsCacheName;
    }

    /**
     * Returns the cache instance to use for storing active sessions.  If one is not available (it is {@code null}),
     * it will be {@link CacheManager#getCache(String) acquired} from the {@link #setCacheManager configured}
     * {@code CacheManager} using the {@link #getActiveSessionsCacheName() activeSessionsCacheName}.
     *
     * @return the cache instance to use for storing active sessions or {@code null} if the {@code Cache} instance
     *         should be retrieved from the
     */
    public Cache<Serializable, Session> getActiveSessionsCache() {
        return this.activeSessions;
    }

    /**
     * Sets the cache instance to use for storing active sessions.  If one is not set (it remains {@code null}),
     * it will be {@link CacheManager#getCache(String) acquired} from the {@link #setCacheManager configured}
     * {@code CacheManager} using the {@link #getActiveSessionsCacheName() activeSessionsCacheName}.
     *
     * @param cache the cache instance to use for storing active sessions or {@code null} if the cache is to be
     *              acquired from the {@link #setCacheManager configured} {@code CacheManager}.
     */
    public void setActiveSessionsCache(Cache<Serializable, Session> cache) {
        this.activeSessions = cache;
    }

    /**
     * Returns the active sessions cache, but if that cache instance is null, first lazily creates the cache instance
     * via the {@link #createActiveSessionsCache()} method and then returns the instance.
     * <p/>
     * Note that this method will only return a non-null value code if the {@code CacheManager} has been set.  If
     * not set, there will be no cache.
     *
     * @return the active sessions cache instance.
     */
    private Cache<Serializable, Session> getActiveSessionsCacheLazy() {
        if (this.activeSessions == null) {
            this.activeSessions = createActiveSessionsCache();
        }
        return activeSessions;
    }

    /**
     * Creates a cache instance used to store active sessions.  Creation is done by first
     * {@link #getCacheManager() acquiring} the {@code CacheManager}.  If the cache manager is not null, the
     * cache returned is that resulting from the following call:
     * <pre>       String name = {@link #getActiveSessionsCacheName() getActiveSessionsCacheName()};
     * cacheManager.getCache(name);</pre>
     *
     * @return a cache instance used to store active sessions, or {@code null} if the {@code CacheManager} has
     *         not been set.
     */
    protected Cache<Serializable, Session> createActiveSessionsCache() {
        Cache<Serializable, Session> cache = null;
        CacheManager mgr = getCacheManager();
        if (mgr != null) {
            String name = getActiveSessionsCacheName();
            cache = mgr.getCache(name);
        }
        return cache;
    }

    /**
     * Calls {@code super.create(session)}, then caches the session keyed by the returned {@code sessionId}, and then
     * returns this {@code sessionId}.
     *
     * @param session Session object to create in the EIS and then cache.
     */
    public Serializable create(Session session) {
        Serializable sessionId = super.create(session);
        cache(session, sessionId);
        return sessionId;
    }

    /**
     * Returns the cached session with the corresponding {@code sessionId} or {@code null} if there is
     * no session cached under that id (or if there is no Cache).
     *
     * @param sessionId the id of the cached session to acquire.
     * @return the cached session with the corresponding {@code sessionId}, or {@code null} if the session
     *         does not exist or is not cached.
     */
    protected Session getCachedSession(Serializable sessionId) {
        Session cached = null;
        if (sessionId != null) {
            Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
            if (cache != null) {
                cached = getCachedSession(sessionId, cache);
            }
        }
        return cached;
    }

    /**
     * Returns the Session with the specified id from the specified cache.  This method simply calls
     * {@code cache.get(sessionId)} and can be overridden by subclasses for custom acquisition behavior.
     *
     * @param sessionId the id of the session to acquire.
     * @param cache     the cache to acquire the session from
     * @return the cached session, or {@code null} if the session wasn't in the cache.
     */
    protected Session getCachedSession(Serializable sessionId, Cache<Serializable, Session> cache) {
        return cache.get(sessionId);
    }

    /**
     * Caches the specified session under the cache entry key of {@code sessionId}.
     *
     * @param session   the session to cache
     * @param sessionId the session id, to be used as the cache entry key.
     * @since 1.0
     */
    protected void cache(Session session, Serializable sessionId) {
        if (session == null || sessionId == null) {
            return;
        }
        Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
        if (cache == null) {
            return;
        }
        cache(session, sessionId, cache);
    }

    /**
     * Caches the specified session in the given cache under the key of {@code sessionId}.  This implementation
     * simply calls {@code cache.put(sessionId,session)} and can be overridden for custom behavior.
     *
     * @param session   the session to cache
     * @param sessionId the id of the session, expected to be the cache key.
     * @param cache     the cache to store the session
     */
    protected void cache(Session session, Serializable sessionId, Cache<Serializable, Session> cache) {
        cache.put(sessionId, session);
    }

    /**
     * Attempts to acquire the Session from the cache first using the session ID as the cache key.  If no session
     * is found, {@code super.readSession(sessionId)} is called to perform the actual retrieval.
     *
     * @param sessionId the id of the session to retrieve from the EIS.
     * @return the session identified by {@code sessionId} in the EIS.
     * @throws UnknownSessionException if the id specified does not correspond to any session in the cache or EIS.
     */
    public Session readSession(Serializable sessionId) throws UnknownSessionException {
        Session s = getCachedSession(sessionId);
        if (s == null) {
            s = super.readSession(sessionId);
        }
        return s;
    }

    /**
     * Updates the state of the given session to the EIS by first delegating to
     * {@link #doUpdate(org.apache.shiro.session.Session)}.  If the session is a {@link ValidatingSession}, it will
     * be added to the cache only if it is {@link ValidatingSession#isValid()} and if invalid, will be removed from the
     * cache.  If it is not a {@code ValidatingSession} instance, it will be added to the cache in any event.
     *
     * @param session the session object to update in the EIS.
     * @throws UnknownSessionException if no existing EIS session record exists with the
     *                                 identifier of {@link Session#getId() session.getId()}
     */
    public void update(Session session) throws UnknownSessionException {
        doUpdate(session);
        if (session instanceof ValidatingSession) {
            if (((ValidatingSession) session).isValid()) {
                cache(session, session.getId());
            } else {
                uncache(session);
            }
        } else {
            cache(session, session.getId());
        }
    }

    /**
     * Subclass implementation hook to actually persist the {@code Session}'s state to the underlying EIS.
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
        uncache(session);
        doDelete(session);
    }

    /**
     * Subclass implementation hook to permanently delete the given Session from the underlying EIS.
     *
     * @param session the session instance to permanently delete from the EIS.
     */
    protected abstract void doDelete(Session session);

    /**
     * Removes the specified Session from the cache.
     *
     * @param session the session to remove from the cache.
     */
    protected void uncache(Session session) {
        if (session == null) {
            return;
        }
        Serializable id = session.getId();
        if (id == null) {
            return;
        }
        Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
        if (cache != null) {
            cache.remove(id);
        }
    }

    /**
     * Returns all active sessions in the system.
     * <p/>
     * <p>This implementation merely returns the sessions found in the activeSessions cache.  Subclass implementations
     * may wish to override this method to retrieve them in a different way, perhaps by an RDBMS query or by other
     * means.
     *
     * @return the sessions found in the activeSessions cache.
     */
    public Collection<Session> getActiveSessions() {
        Cache<Serializable, Session> cache = getActiveSessionsCacheLazy();
        if (cache != null) {
            return cache.values();
        } else {
            return Collections.emptySet();
        }
    }
}
