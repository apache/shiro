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
package org.jsecurity;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
import org.jsecurity.cache.HashtableCacheProvider;
import org.jsecurity.cache.ehcache.EhCacheProvider;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.JavaEnvironment;
import org.jsecurity.util.LifecycleUtils;

/**
 *
 * A very basic extension point for the SecurityManager interface that merely provides logging and caching 
 * support.  All <tt>SecurityManager</tt> method implementations are left to subclasses.
 *
 * <p>Upon {@link #init() initialization}, a sensible default <tt>CacheProvider</tt> will be created automatically
 * if one has not been provided.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class CachingSecurityManager implements SecurityManager, Initializable, Destroyable, CacheProviderAware {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected CacheProvider cacheProvider;

    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public CachingSecurityManager() {
    }

    /**
     * Returns the default CacheProvider used by this SecurityManager.
     *
     * @return the cacheProvider used by this SecurityManager
     */
    public CacheProvider getCacheProvider() {
        return cacheProvider;
    }

    public void setCacheProvider(CacheProvider cacheProvider) {
        this.cacheProvider = cacheProvider;
    }

    public void init() {
        ensureCacheProvider();
        afterCacheProviderSet();
    }

    protected void ensureCacheProvider() {
        if (getCacheProvider() == null) {
            CacheProvider provider = createCacheProvider();
            setCacheProvider(provider);
        }
    }

    protected CacheProvider createCacheProvider() {
        CacheProvider provider;

        if (JavaEnvironment.isEhcacheAvailable()) {
            if (log.isDebugEnabled()) {
                String msg = "Initializing default CacheProvider using EhCache.";
                log.debug(msg);
            }
            EhCacheProvider ehCacheProvider = new EhCacheProvider();
            ehCacheProvider.init();
            provider = ehCacheProvider;
        } else {
            if (log.isWarnEnabled()) {
                String msg = "Instantiating default CacheProvider which will create in-memory HashTable caches.  " +
                    "This is NOT RECOMMENDED for production environments.  Please ensure ehcache.jar is in the " +
                    "classpath and JSecurity will automatically use a production-quality CacheProvider " +
                    "implementation, or you may alternatively provide your own via the #setCacheProvider method.";
                log.warn(msg);
            }
            provider = new HashtableCacheProvider();
        }

        return provider;
    }

    protected void afterCacheProviderSet(){}

    public void destroy() {
        beforeCacheProviderDestroyed();
        destroyCacheProvider();
    }

    protected void beforeCacheProviderDestroyed(){}    

    protected void destroyCacheProvider() {
        LifecycleUtils.destroy( getCacheProvider() );
        this.cacheProvider = null;
    }
}
