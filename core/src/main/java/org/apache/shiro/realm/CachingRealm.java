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
package org.apache.shiro.realm;

import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.cache.CacheManagerAware;
import org.apache.shiro.util.Nameable;

import java.util.concurrent.atomic.AtomicInteger;


/**
 * A very basic abstract extension point for the {@link Realm} interface that provides caching support.
 * <p/>
 * All actual Realm method implementations are left to subclasses.
 *
 * @since 0.9
 */
public abstract class CachingRealm implements Realm, Nameable, CacheManagerAware {

    //TODO - complete JavaDoc

    private static final AtomicInteger INSTANCE_COUNT = new AtomicInteger();

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private String name;
    private boolean cachingEnabled;
    private CacheManager cacheManager;

    public CachingRealm() {
        this.cachingEnabled = true;
        this.name = getClass().getName() + "_" + INSTANCE_COUNT.getAndIncrement();
    }

    /**
     * Returns the <tt>CacheManager</tt> used for data caching to reduce EIS round trips, or <tt>null</tt> if
     * caching is disabled.
     *
     * @return the <tt>CacheManager</tt> used for data caching to reduce EIS round trips, or <tt>null</tt> if
     *         caching is disabled.
     */
    public CacheManager getCacheManager() {
        return this.cacheManager;
    }

    /**
     * Sets the <tt>CacheManager</tt> to be used for data caching to reduce EIS round trips.
     * <p/>
     * <p>This property is <tt>null</tt> by default, indicating that caching is turned off.
     *
     * @param cacheManager the <tt>CacheManager</tt> to use for data caching, or <tt>null</tt> to disable caching.
     */
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        afterCacheManagerSet();
    }

    /**
     * Returns {@code true} if caching should be used if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}, {@code false} otherwise.
     * <p/>
     * The default value is {@code true} since the large majority of Realms will benefit from caching if a CacheManager
     * has been configured.  However, memory-only realms should set this value to {@code false} since they would
     * manage account data in memory already lookups would already be as efficient as possible.
     *
     * @return {@code true} if caching will be globally enabled if a {@link CacheManager} has been
     *         configured, {@code false} otherwise
     */
    public boolean isCachingEnabled() {
        return cachingEnabled;
    }

    /**
     * Sets whether or not caching should be used if a {@link CacheManager} has been
     * {@link #setCacheManager(org.apache.shiro.cache.CacheManager) configured}.
     *
     * @param cachingEnabled whether or not to globally enable caching for this realm.
     */
    public void setCachingEnabled(boolean cachingEnabled) {
        this.cachingEnabled = cachingEnabled;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    protected void afterCacheManagerSet() {
    }
}
