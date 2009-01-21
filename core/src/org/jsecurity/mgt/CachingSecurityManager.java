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

import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.cache.DefaultCacheManager;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.LifecycleUtils;

/**
 * A very basic starting point for the SecurityManager interface that merely provides logging and caching
 * support.  All actual {@code SecurityManager} method implementations are left to subclasses.
 *
 * <p>Upon instantiation, a sensible default {@link CacheManager CacheManager} will be created automatically.  This
 * {@code CacheManager} can then be used by subclass implementations and children components for use to achieve better
 * application performance if so desired.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class CachingSecurityManager implements SecurityManager, Destroyable, CacheManagerAware {

    /**
     * The CacheManager to use to perform caching operations to enhance performance.  Can be null.
     */
    private CacheManager cacheManager;

    /**
     * Default no-arg constructor that will automatically attempt to initialize a default cacheManager
     */
    public CachingSecurityManager() {
        this.cacheManager = new DefaultCacheManager();
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
     * Destroys the {@link #getCacheManager() cacheManager} via {@link LifecycleUtils#destroy LifecycleUtils.destroy}.
     */
    public void destroy() {
        LifecycleUtils.destroy(getCacheManager());
        this.cacheManager = null;
    }
}
