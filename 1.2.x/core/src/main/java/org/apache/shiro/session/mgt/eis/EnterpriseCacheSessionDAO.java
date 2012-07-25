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

import org.apache.shiro.cache.AbstractCacheManager;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.MapCache;
import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SessionDAO implementation that relies on an enterprise caching product as the EIS system of record for all sessions.
 * It is expected that an injected {@link org.apache.shiro.cache.Cache Cache} or
 * {@link org.apache.shiro.cache.CacheManager CacheManager} is backed by an enterprise caching product that can support
 * all application sessions and/or provide disk paging for resilient data storage.
 * <h2>Production Note</h2>
 * This implementation defaults to using an in-memory map-based {@code CacheManager}, which is great for testing but
 * will typically not scale for production environments and could easily cause {@code OutOfMemoryException}s.  Just
 * don't forget to configure<b>*</b> an instance of this class with a production-grade {@code CacheManager} that can
 * handle disk paging for large numbers of sessions and you'll be fine.
 * <p/>
 * <b>*</b>If you configure Shiro's {@code SecurityManager} instance with such a {@code CacheManager}, it will be
 * automatically applied to an instance of this class and you won't need to explicitly set it in configuration.
 * <h3>Implementation Details</h3>
 * This implementation relies heavily on the {@link CachingSessionDAO parent class}'s transparent caching behavior for
 * all storage operations with the enterprise caching product.  Because the parent class uses a {@code Cache} or
 * {@code CacheManager} to perform caching, and the cache is considered the system of record, nothing further needs to
 * be done for the {@link #doReadSession}, {@link #doUpdate} and {@link #doDelete} method implementations.  This class
 * implements those methods as required by the parent class, but they essentially do nothing.
 *
 * @since 1.0
 */
public class EnterpriseCacheSessionDAO extends CachingSessionDAO {

    public EnterpriseCacheSessionDAO() {
        setCacheManager(new AbstractCacheManager() {
            @Override
            protected Cache<Serializable, Session> createCache(String name) throws CacheException {
                return new MapCache<Serializable, Session>(name, new ConcurrentHashMap<Serializable, Session>());
            }
        });
    }

    protected Serializable doCreate(Session session) {
        Serializable sessionId = generateSessionId(session);
        assignSessionId(session, sessionId);
        return sessionId;
    }

    protected Session doReadSession(Serializable sessionId) {
        return null; //should never execute because this implementation relies on parent class to access cache, which
        //is where all sessions reside - it is the cache implementation that determines if the
        //cache is memory only or disk-persistent, etc.
    }

    protected void doUpdate(Session session) {
        //does nothing - parent class persists to cache.
    }

    protected void doDelete(Session session) {
        //does nothing - parent class removes from cache.
    }
}
