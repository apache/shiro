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
package org.jsecurity.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.cache.DefaultCacheManager;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.LifecycleUtils;

/**
 * A very basic extension point for the SecurityManager interface that merely provides logging and caching
 * support.  All <tt>SecurityManager</tt> method implementations are left to subclasses.
 *
 * <p>Upon instantiation, a sensible default {@link CacheManager CacheManager} will be created automatically via the
 * {@link #createCacheManager() createCacheManager() method.  This <code>CacheManager</code>
 * can then be used by subclass implementations and children components for use to achieve better application
 * performance.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class CachingSecurityManager implements SecurityManager, Destroyable, CacheManagerAware {

    /**
     * Internal private static log instance.
     */
    private static final Log log = LogFactory.getLog(CachingSecurityManager.class);

    /**
     * The CacheManager to use to perform caching operations to enhance performance.  Can be null.
     */
    protected CacheManager cacheManager;

    /**
     * Default no-arg constructor that will automatically attempt to initialize a default cacheManager
     */
    public CachingSecurityManager() {
        setCacheManager(createCacheManager());
    }

    /**
     * Returns the CacheManager used by this SecurityManager.
     *
     * @return the cacheManager used by this SecurityManager
     */
    public CacheManager getCacheManager() {
        return cacheManager;
    }

    /**
     * Sets the CacheManager used by this <code>SecurityManager</code> and potentially any of its
     * children components.
     * <p/>
     * After the cacheManager attribute has been set, the template method
     * {@link #afterCacheManagerSet afterCacheManagerSet()} is executed to allow subclasses to adjust when a
     * cacheManager is available.
     *
     * @param cacheManager the CacheManager used by this <code>SecurityManager</code> and potentially any of its
     *                     children components.
     */
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        afterCacheManagerSet();
    }


    /**
     * Template callback to notify subclasses that a
     * {@link CacheManager CacheManager} has been set and is available for use via the
     * {@link #getCacheManager getCacheManager()} method.
     */
    protected void afterCacheManagerSet() {
    }

    /**
     * Creates a {@link CacheManager CacheManager} instance to be used by this <code>SecurityManager</code>
     * and potentially any of its children components.
     * <p/>
     * This default implementation returns a new
     * {@link org.jsecurity.cache.DefaultCacheManager DefaultCacheManager}, which uses in-memory (memory-leak safe)
     * caches which are production safe.
     * <p/>
     * This can be overridden by subclasses for a different implementation, but it is often easier to set a
     * different implementation via the {@link #setCacheManager(org.jsecurity.cache.CacheManager) setCacheManager}
     * method, for example in code or Dependency Injection frameworks (a la Spring or JEE 3).
     *
     * @return a newly created <code>CacheManager</code> instance.
     */
    protected CacheManager createCacheManager() {
        return new DefaultCacheManager();
    }

    /**
     * First calls {@link #beforeCacheManagerDestroyed() beforeCacheManagerDestroyed()} to allow subclasses to clean up
     * first, then calls {@link #destroyCacheManager() destroyCacheManager()} to clean up the internal
     * {@link CacheManager CacheManager}.
     */
    public void destroy() {
        beforeCacheManagerDestroyed();
        destroyCacheManager();
    }

    /**
     * Template hook for subclasses to perform cleanup behavior during shutdown.
     */
    protected void beforeCacheManagerDestroyed() {
    }

    /**
     * Cleans up the internal <code>CacheManager</code> instance during shutdown.
     */
    protected void destroyCacheManager() {
        LifecycleUtils.destroy(getCacheManager());
    }
}
