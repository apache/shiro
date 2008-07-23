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
import org.jsecurity.cache.ehcache.EhCacheManager;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.LifecycleUtils;

/**
 * A very basic extension point for the SecurityManager interface that merely provides logging and caching
 * support.  All <tt>SecurityManager</tt> method implementations are left to subclasses.
 *
 * <p>Upon instantiation, a sensible default <tt>CacheManager</tt> will be attempted to be created automatically.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class CachingSecurityManager implements SecurityManager, Destroyable, CacheManagerAware {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected CacheManager cacheManager = createCacheManager();

    /**
     * Default no-arg constructor.
     */
    public CachingSecurityManager() {
    }

    /**
     * Returns the default CacheManager used by this SecurityManager.
     *
     * @return the cacheManager used by this SecurityManager
     */
    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
        afterCacheManagerSet();
    }

    protected void afterCacheManagerSet() {
    }

    protected CacheManager createCacheManager() {
        CacheManager manager = null;

        if (log.isDebugEnabled()) {
            log.debug("Attempting to initialize default CacheManager using EhCache...");
        }

        try {
            EhCacheManager ehCacheManager = new EhCacheManager();
            ehCacheManager.init();
            manager = ehCacheManager;
        } catch (NoClassDefFoundError e) {
            if (log.isDebugEnabled()) {
                log.debug("Ehcache was not found in the classpath. A default EhCacheManager cannot be created.");
            }
        }

        return manager;
    }

    public void destroy() {
        beforeCacheManagerDestroyed();
        destroyCacheManager();
    }

    protected void beforeCacheManagerDestroyed() {
    }

    protected void destroyCacheManager() {
        LifecycleUtils.destroy(getCacheManager());
    }
}
