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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.session.support.eis.CachingSessionDAO;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;

import java.io.InputStream;

/**
 * <p>JSecurity {@link CacheProvider} for ehcache 1.2 and above.</p>
 *
 * <p>This provider requires EhCache 1.2 and above. Make sure EhCache 1.1 or earlier
 * is not in the classpath or it will not work.</p>
 *
 * <p>See http://ehcache.sf.net for documentation on EhCache</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class EhCacheProvider implements CacheProvider, Initializable, Destroyable {

    public static final String DEFAULT_ACTIVE_SESSIONS_CACHE_NAME = CachingSessionDAO.ACTIVE_SESSION_CACHE_NAME;
    public static final int DEFAULT_ACTIVE_SESSIONS_CACHE_MAX_ELEM_IN_MEM = 20000;
    public static final int DEFAULT_ACTIVE_SESSIONS_DISK_EXPIRY_THREAD_INTERVAL_SECONDS = 600;

    /**
     * Commons-logging logger
     */
    protected final transient Log log = LogFactory.getLog( getClass() );

    /**
     * The EhCache cache manager used by this provider to create caches.
     */
    protected CacheManager manager;
    private boolean cacheManagerImplicitlyCreated = false;
    /**
     * Classpath file location - without a leading slash, it is relative to the current class.
     */
    private String cacheManagerConfigFile = "ehcache.xml";

    public CacheManager getCacheManager() {
        return manager;
    }

    public void setCacheManager( CacheManager manager ) {
        this.manager = manager;
    }

    public String getCacheManagerConfigFile() {
        return this.cacheManagerConfigFile;
    }

    public void setCacheManagerConfigFile( String classpathLocation ) {
        this.cacheManagerConfigFile = classpathLocation;
    }

    protected InputStream getCacheManagerConfigFileInputStream() {
        String classpathLocation = getCacheManagerConfigFile();
        return getClass().getResourceAsStream( classpathLocation );
    }

    /**
     * Loads an existing EhCache from the cache manager, or starts a new cache if one is not found.
     *
     * @param name the name of the cache to load/create.
     */
    public final Cache buildCache( String name ) throws CacheException {

        if ( log.isDebugEnabled() ) {
            log.debug( "Loading a new EhCache cache named [" + name + "]" );
        }

        try {
            net.sf.ehcache.Cache cache = getCacheManager().getCache( name );
            if ( cache == null ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "Could not find a specific ehcache configuration for cache named [" + name + "]; using defaults." );
                }
                if ( name.equals( DEFAULT_ACTIVE_SESSIONS_CACHE_NAME ) ) {
                    if ( log.isInfoEnabled() ) {
                        log.info( "Creating " + DEFAULT_ACTIVE_SESSIONS_CACHE_NAME + " cache with default JSecurity " +
                            "session cache settings." );
                    }
                    cache = buildDefaultActiveSessionsCache();
                    manager.addCache( cache );
                } else {
                    manager.addCache( name );
                }

                cache = manager.getCache( name );
                
                if ( log.isDebugEnabled() ) {
                    log.debug( "Started EHCache named [" + name + "]" );
                }
            }
            return new EhCache( cache, getCacheManager() );
        } catch ( net.sf.ehcache.CacheException e ) {
            throw new CacheException( e );
        }
    }

    private net.sf.ehcache.Cache buildDefaultActiveSessionsCache() throws CacheException {
        return new net.sf.ehcache.Cache( DEFAULT_ACTIVE_SESSIONS_CACHE_NAME,
            DEFAULT_ACTIVE_SESSIONS_CACHE_MAX_ELEM_IN_MEM,
            true,
            true,
            0,
            0,
            true,
            DEFAULT_ACTIVE_SESSIONS_DISK_EXPIRY_THREAD_INTERVAL_SECONDS );
    }

    /**
     * Initializes this cache provider.
     * <p/>
     * <p>If a {@link #setCacheManager CacheManager} has been
     * explicitly set (e.g. via Dependency Injection or programatically) prior to calling this
     * method, this method does nothing.
     * <p>However, if no <tt>CacheManager</tt> has been set, the default Ehcache singleton will be initialized, where
     * Ehcache will look for an <tt>ehcache.xml</tt> file at the root of the classpath.  If one is not found,
     * Ehcache will use its own failsafe configuration file.
     * <p/>
     * <p>Because JSecurity cannot use the failsafe defaults (failsafe expunges cached objects after 2 minutes,
     * something not desireable for JSecurity sessions), this class manages an internal default configuration for
     * this case.</p>
     *
     * @throws org.jsecurity.cache.CacheException
     *          if there are any CacheExceptions thrown by EhCache.
     * @see CacheManager#create
     */
    public final void init() throws CacheException {
        try {
            CacheManager cacheMgr = getCacheManager();
            if ( cacheMgr == null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "cacheManager property not set.  Constructing CacheManager instance... " );
                }
                //using the CacheManager constructor, the resulting instance is _not_ a VM singleton
                //(as would be the case by calling CacheManager.getInstance().  We do not use the getInstance here
                //because we need to know if we need to destroy the CacheManager instance - using the static call,
                //we don't know which component is responsible for shutting it down.  By using a single EhCacheProvider,
                //it will always know to shut down the instance if it was responsible for creating it.
                cacheMgr = new CacheManager( getCacheManagerConfigFileInputStream() );
                cacheManagerImplicitlyCreated = true;
                setCacheManager( cacheMgr );
            }
        } catch ( Exception e ) {
            throw new CacheException( e );
        }
    }

    public void destroy() {
        if ( cacheManagerImplicitlyCreated ) {
            try {
                CacheManager cacheMgr = getCacheManager();
                cacheMgr.shutdown();
            } catch ( Exception e ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "Unable to cleanly shutdown implicitly created CacheManager instance.  " +
                        "Ignoring (shutting down)..." );
                }
            }
            cacheManagerImplicitlyCreated = false;
        }
    }
}
