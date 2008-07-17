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
import org.jsecurity.util.Initializable;
import org.jsecurity.util.JavaEnvironment;
import org.jsecurity.util.LifecycleUtils;

/**
 * A very basic extension point for the SecurityManager interface that merely provides logging and caching
 * support.  All <tt>SecurityManager</tt> method implementations are left to subclasses.
 *
 * <p>Upon {@link #init() initialization}, a sensible default <tt>CacheManager</tt> will be created automatically
 * if one has not been provided.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class CachingSecurityManager implements SecurityManager, Initializable, Destroyable, CacheManagerAware {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected CacheManager cacheManager = null;

    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after first setting necessary attributes.
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
    }

    public void init() {
        ensureCacheManager();
        afterCacheManagerSet();
    }

    protected void ensureCacheManager() {
        CacheManager cacheManager = getCacheManager();
        if (cacheManager == null) {
            if (log.isDebugEnabled()) {
                log.debug("No CacheManager has been configured.  Attempting to create a default one...");
            }
            CacheManager manager = createCacheManager();
            if (manager != null) {
                setCacheManager(manager);
            } else {
                if (log.isInfoEnabled()) {
                    String msg = "No explicit CacheManager has been configured/injected and Ehcache was not found in " +
                            "the classpath with which to create a default CacheManager.  Caching is disabled for " +
                            "this SecurityManager instance and any of its implicitly created children objects. \n\n" +
                            "If you wish to enhance application performance, you should inject your own " +
                            CacheManager.class.getName() + " instance via the setCacheManager method, or simply " +
                            "include ehcache.jar in the classpath to use a suitable default.";
                    log.info(msg);
                }
            }
        } else {
            if (log.isInfoEnabled()) {
                log.info("Using configured CacheManager [" + cacheManager + "]");
            }
        }
    }

    protected CacheManager createCacheManager() {
        CacheManager manager = null;

        if (JavaEnvironment.isEhcacheAvailable()) {
            if (log.isDebugEnabled()) {
                String msg = "Initializing default CacheManager using EhCache.";
                log.debug(msg);
            }
            EhCacheManager ehCacheManager = new EhCacheManager();
            ehCacheManager.init();
            manager = ehCacheManager;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Ehcache was not found in the classpath. A default EhCacheManager cannot be created.");
            }
        }

        return manager;
    }

    protected void afterCacheManagerSet() {
    }

    public void destroy() {
        beforeCacheManagerDestroyed();
        destroyCacheManager();
    }

    protected void beforeCacheManagerDestroyed() {
    }

    protected void destroyCacheManager() {
        LifecycleUtils.destroy(getCacheManager());
        this.cacheManager = null;
    }
}
