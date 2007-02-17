/*
* Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.cache.ehcache;

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.util.ClassLoaderUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.util.Initializable;

import java.net.URL;

/**
 * <p>JSecurity {@link CacheProvider} for ehcache 1.2.</p>
 * <p/>
 * <p>This provider requires EhCache 1.2. Make sure EhCache 1.1 or earlier
 * is not in the classpath or it will not work.</p>
 * <p/>
 * <p>See http://ehcache.sf.net for documentation on EhCache</p>
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.2
 */
public class EhCacheProvider implements CacheProvider, Initializable {

    /**
     * Commons-logging logger
     */
    protected final transient Log log = LogFactory.getLog(getClass());

    /**
     * The EhCache cache manager used by this provider to create caches.
     */
    private CacheManager manager;

    private static final String DEFAULT_CONFIGURATION_RESOURCE_NAME = "jsecurity-failsafe.ehcache.xml";

    private String configurationResourceName = null;
    private boolean managerCreatedImplicitly = false;

    public CacheManager getCacheManager() {
        return manager;
    }

    public void setCacheManager(CacheManager manager) {
        this.manager = manager;
    }

    public String getConfigurationResourceName() {
        return configurationResourceName;
    }

    public void setConfigurationResourceName(String configurationResourceName) {
        this.configurationResourceName = configurationResourceName;
    }


    /**
     * Loads an existing EhCache from the cache manager, or starts a new cache if one is not found.
     *
     * @param name the name of the cache to load/create.
     */
    public final Cache buildCache(String name) throws CacheException {

        if (log.isDebugEnabled()) {
            log.debug("Loading a new EhCache cache named [" + name + "]");
        }

        try {
            net.sf.ehcache.Cache cache = getCacheManager().getCache(name);
            if (cache == null) {

                if (log.isWarnEnabled()) {
                    log.warn("Could not find a specific ehcache configuration for cache named [" + name + "]; using defaults.");
                }

                manager.addCache(name);
                cache = manager.getCache(name);

                if (log.isDebugEnabled()) {
                    log.debug("Started EHCache named [" + name + "]");
                }
            }
            return new EhCache(cache);
        } catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }


    /**
     * Initializes this cache provider.
     * <p/>
     * <p>If a {@link #setCacheManager CacheManager} has been
     * explicitly set (e.g. via Dependency Injection or programatically) prior to calling this
     * method, this method does nothing.
     * <p>However, if no <tt>CacheManager</tt> has been set, one will be created by first
     * looking for an Ehcache config in the classpath at the
     * {@link #getConfigurationResourceName()} location, and using that config to construct the
     * manager.
     * <p>If both the <tt>CacheManager</tt> and <tt>configurationResourceName</tt> properties
     * have not been set, a default <tt>CacheManager</tt> implementation will be created and used.
     *
     * @throws org.jsecurity.cache.CacheException
     *          if there are any CacheExceptions thrown by EhCache.
     * @see #destroy
     */
    public final void init() throws CacheException {
        try {
            CacheManager cacheMgr = getCacheManager();
            if (cacheMgr == null) {
                if (log.isDebugEnabled()) {
                    log.debug("cacheManager property not set.  Attempting to create one from " +
                            "configurationResource...");
                }

                String cfgName = getConfigurationResourceName();

                if (cfgName == null) {
                    if (log.isInfoEnabled()) {
                        String msg = "No ehcache configuration resource name set (i.e. ehcache.xml).  Using default " +
                                "JSecurity ehcache configuration located in the classpath at /" +
                                DEFAULT_CONFIGURATION_RESOURCE_NAME + ".";
                        log.info(msg);
                    }
                    cfgName = "/" + DEFAULT_CONFIGURATION_RESOURCE_NAME;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Creating CacheManager from configurationResourceName [" +
                            cfgName + "]");
                }
                if (!cfgName.startsWith("/")) {
                    cfgName = "/" + cfgName;
                    if (log.isDebugEnabled()) {
                        log.debug("prepending '/' to " + cfgName + ". This file should be placed " +
                                "in the root of the classpath rather than in a package.");
                    }
                }
                URL url = loadResource(cfgName);
                setCacheManager(new CacheManager(url));
                managerCreatedImplicitly = true;
            }
        } catch (net.sf.ehcache.CacheException e) {
            throw new CacheException(e);
        }
    }


    /**
     * Helper method to load the configuration resource from the classpath.
     *
     * @param configurationResourceName the name of the configuration file to be loaded.
     * @return the URL for the configuration file with the given name in the classpath.
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
        if (log.isDebugEnabled()) {
            log.debug("Found resource [" + configurationResourceName +
                    "] - resolved to URL [" + url + "]");
        }
        return url;
    }

    /**
     * If this provider was responsible for implicitly creating the internal Ehcache {@link CacheManager},
     * it will call the manager's {@link CacheManager#shutdown shutdown} method.
     * <p/>
     * <p>If this provider
     * <em>did not</em> implicitly create the manager (e.g. because it was created by a DI framework
     * or explicitly by programming), this method does nothing.  In this case, it is assumed that
     * whichever party created the manager would also destroy it.
     *
     * @see #init
     */
    public final void destroy() {
        //Only manage the lifecycle of the manager if this object was the one that created it.
        //Otherwise, the manager was set explicitly (DI, manually, etc), so it is the responsibility
        //of the party that created it to destroy it.
        if (managerCreatedImplicitly) {
            CacheManager mgr = getCacheManager();
            if (mgr != null) {
                mgr.shutdown();
                setCacheManager(null);
            }
            managerCreatedImplicitly = false;
        }
    }

}