/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.cache.HashtableCacheManager;
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
 * @since 0.9
 */
public abstract class CachingSecurityManager implements SecurityManager, Initializable, Destroyable, CacheManagerAware {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected CacheManager cacheManager;

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
            if ( log.isDebugEnabled() ) {
                log.debug( "No CacheManager has been configured.  Attempting to create a default one..." );
            }
            CacheManager manager = createCacheManager();
            setCacheManager(manager);
        } else {
            if ( log.isInfoEnabled() ) {
                log.info( "Using configured CacheManager [" + cacheManager + "]" );
            }
        }
    }

    protected CacheManager createCacheManager() {
        CacheManager manager;

        if (JavaEnvironment.isEhcacheAvailable()) {
            if (log.isDebugEnabled()) {
                String msg = "Initializing default CacheManager using EhCache.";
                log.debug(msg);
            }
            EhCacheManager ehCacheManager = new EhCacheManager();
            ehCacheManager.init();
            manager = ehCacheManager;
        } else {
            if (log.isWarnEnabled()) {
                String msg = "Ehcache was not found in the classpath.  Reverting to failsafe CacheManager which will " +
                        "create in-memory HashTable caches.  This is NOT RECOMMENDED for production environments.  " +
                        "Please ensure ehcache.jar is in the classpath and JSecurity will automatically use a " +
                        "production-quality CacheManager implementation, or you may alternatively provide your " +
                        "own via the " + getClass().getName() + "#setCacheManager method.";
                log.warn(msg);
            }
            manager = new HashtableCacheManager();
        }

        return manager;
    }

    protected void afterCacheManagerSet(){}

    public void destroy() {
        beforeCacheManagerDestroyed();
        destroyCacheManager();
    }

    protected void beforeCacheManagerDestroyed(){}

    protected void destroyCacheManager() {
        LifecycleUtils.destroy( getCacheManager() );
        this.cacheManager = null;
    }
}
