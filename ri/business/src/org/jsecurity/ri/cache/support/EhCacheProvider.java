/*
* Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.ri.cache.support;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.util.ClassLoaderUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.ri.Configuration;
import org.jsecurity.ri.cache.Cache;
import org.jsecurity.ri.cache.CacheException;
import org.jsecurity.ri.cache.CacheProvider;

import java.net.URL;

/**
 * <p>JSecurity {@link CacheProvider} for ehcache 1.2.</p>
 *
 * <p>This provider requires EhCache 1.2. Make sure EhCache 1.1 or earlier
 * is not in the classpath or it will not work.</p>
 *
 * <p>See http://ehcache.sf.net for documentation on EhCache</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class EhCacheProvider implements CacheProvider {

    /**
     * The property that can be used to override the name of the ehcache configuration file
     */
    public static final String NET_SF_EHCACHE_CONFIGURATION_RESOURCE_NAME =
        "net.sf.ehcache.configurationResourceName";

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The EhCache cache manager used by this provider to create caches.
     */
    private CacheManager manager;


    /**
     * Loads an existing EhCache from the cache manager, or starts a new cache if one is not found.
     * @param name the name of the cache to load/create.
     * @param config the JSecurity configuration associated with this deployment.
     */
    public final Cache buildCache(String name, Configuration config) throws CacheException {

        if (logger.isDebugEnabled()) {
            logger.debug("Loading a new EhCache cache named [" + name + "]");
        }

        try {
            net.sf.ehcache.Cache cache = manager.getCache(name);
            if (cache == null) {

                if( logger.isWarnEnabled() ) {
                    logger.warn("Could not find a specific ehcache configuration for cache named [" + name + "]; using defaults.");
                }

                manager.addCache(name);
                cache = manager.getCache(name);

                if( logger.isDebugEnabled() ) {
                    logger.debug("Started EHCache named [" + name + "]");
                }
            }
            return new org.jsecurity.ri.cache.support.EhCache(cache);
        } catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }


    /**
     * Initializes this cache provider with the given configuration.
     * @param config the JSecurity configuration.
     */
    public final void init(Configuration config) throws CacheException {
        try {
            String configurationResourceName = null;

            // If any config properties are present check for the name of the ehcache config to load.
            if (config.getProperties() != null) {
                configurationResourceName = (String) config.getProperties().get(NET_SF_EHCACHE_CONFIGURATION_RESOURCE_NAME);
            }

            if (configurationResourceName == null || configurationResourceName.length() == 0) {
                manager = new CacheManager();
            } else {
                if (!configurationResourceName.startsWith("/")) {
                    configurationResourceName = "/" + configurationResourceName;
                    if (logger.isDebugEnabled()) {
                        logger.debug("prepending / to " + configurationResourceName + ". It should be placed in the root"
                                + "of the classpath rather than in a package.");
                    }
                }
                URL url = loadResource(configurationResourceName);
                manager = new CacheManager(url);
            }
        } catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }


    /**
     * Helper method to load the configuration resource from the class path.
     */
    private URL loadResource(String configurationResourceName) {
        ClassLoader standardClassloader = ClassLoaderUtil.getStandardClassLoader();
        URL url = null;
        if (standardClassloader != null) {
            url = standardClassloader.getResource(configurationResourceName);
        }
        if (url == null) {
            url = this.getClass().getResource(configurationResourceName);
        }
        if (logger.isDebugEnabled()) {
        logger.debug( "Creating EhCacheProvider from resource [" + configurationResourceName + "] " +
                "Resolved to URL [" + url + "]");
        }
        return url;
    }

    /**
     * Shuts down the ehcache cache manaager associated with this provider.
     */
    public final void destroy() {
        if (manager != null) {
            manager.shutdown();
            manager = null;
        }
    }

}