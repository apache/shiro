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

import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
import org.jsecurity.cache.HashtableCacheProvider;
import org.jsecurity.cache.ehcache.EhCacheProvider;
import org.jsecurity.util.JavaEnvironment;
import org.jsecurity.util.LifecycleUtils;

/**
 * JSecurity support of a {@link org.jsecurity.SecurityManager} class hierarcy that provides support for a
 * {@link CacheProvider CacheProvider} and associated convenience methods only.  All actual <tt>SecurityManager</tt>
 * method implementations are left to subclasses.
 *
 * <p>Upon {@link #init() initialization}, a sensible default <tt>CacheProvider</tt> will be created automatically
 * if one has not been provided.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class CachingSecurityManager extends AbstractSecurityManager implements CacheProviderAware {

    protected CacheProvider cacheProvider = null;

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


    protected synchronized void ensureCacheProvider() {
        //only create one if one hasn't been explicitly set by the instantiator
        CacheProvider cacheProvider = getCacheProvider();
        if (cacheProvider == null) {
            cacheProvider = createCacheProvider();
            setCacheProvider(cacheProvider);
        }
    }

    protected void afterCacheProviderSet(){}

    protected void beforeCacheProviderDestroyed(){}    

    protected void destroyCacheProvider() {
        LifecycleUtils.destroy( getCacheProvider() );
        this.cacheProvider = null;
    }

    public void init() {
        super.init();
        ensureCacheProvider();
        afterCacheProviderSet();
    }

    public void destroy() {
        beforeCacheProviderDestroyed();        
        destroyCacheProvider();
        super.destroy();
    }
}
