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

package org.jsecurity.realm.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.realm.Realm;

import java.security.Principal;

/**
 * <p>An abstract implementation of the {@link Realm} interface that enables caching of
 * authorization information returned by subclasses.  This implementation can use a
 * {@link #setAuthorizationInfoCache cache} set explicitly or can create one using a specified
 * {@link #setAuthorizationInfoCacheProvider cacheProvider} to cache authorization information by
 * principal.  See the {@link #init init()} method for more information on how this class
 * implements caching behavior.
 *
 * <p>In general, caching works best if the principals are {@link java.io.Serializable}.
 * The {@link Principal}s <tt>equals()</tt> and <tt>hashCode()</tt> methods must be correct for
 * the caching to be successful.</p>
 *
 *
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class AbstractCachingRealm extends AbstractRealm implements Realm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * The default postfix appended to the realm name for caching authorization information.
     */
    private static final String DEFAULT_AUTHORIZATION_INFO_CACHE_POSTFIX = ".authorization";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The cache used by this realm to store authorization information associated with individual
     * principals.
     */
    private Cache authorizationInfoCache = null;

    /**
     * Upon initialization, if the authorizationInfoCache is null and this attribute has been set
     * (i.e. it is not-null), it will be used to create the authorizationInfoCache.
     */
    private CacheProvider authzInfoCacheProvider = null;

    /**
     * The postfix appended to the realm name used to create the name of the authorization cache.
     */
    private String authorizationInfoCachePostfix = DEFAULT_AUTHORIZATION_INFO_CACHE_POSTFIX ;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthorizationInfoCachePostfix(String authorizationInfoCachePostfix) {
        this.authorizationInfoCachePostfix = authorizationInfoCachePostfix;
    }

    public void setAuthorizationInfoCache(Cache authorizationInfoCache) {
        this.authorizationInfoCache = authorizationInfoCache;
    }

    public Cache getAuthorizationInfoCache() {
        return this.authorizationInfoCache;
    }

    public void setAuthorizationInfoCacheProvider(CacheProvider authzInfoCacheProvider) {
        this.authzInfoCacheProvider = authzInfoCacheProvider;
    }

    public CacheProvider getAuthorizationInfoCacheProvider() {
        return this.authzInfoCacheProvider;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * Initializes this realm and potentially enables a cache, depending on configuration.
     *
     * <p>When this method is called, the following logic is executed:
     * <ol>
     *   <li>If the {@link #setAuthorizationInfoCache cache} property has been set, it will be
     *       used to cache the return values from {@link #getAuthorizationInfo getAuthorizationInfo}
     *       method invocations.
     *       All future calls to <tt>getAuthorizationInfo</tt> will attempt to use this cache first
     *       to aleviate any potential unnecessary calls to an underlying data store.</li>
     *   <li>If the {@link #setAuthorizationInfoCache cache} property has <b>not</b> been set,
     *       the {@link #setAuthorizationInfoCacheProvider cacheProvider} property will be checked.
     *       If a <tt>cacheProvider</tt> has been set, it will be used to create a
     *       <tt>cache</tt>, and this newly created cache which will be used as specified in #1.</li>
     *   <li>If neither the {@link #setAuthorizationInfoCache(org.jsecurity.cache.Cache) cache}
     *       or {@link #setAuthorizationInfoCacheProvider(org.jsecurity.cache.CacheProvider) cacheProvider}
     *       properties are set, caching will be disabled.</li>
     * </ol>
     */
    public void init() {
        if (logger.isDebugEnabled()) {
            logger.debug("Initializing caches for realm [" + getName() + "]");
        }

        Cache cache = getAuthorizationInfoCache();
        if ( cache == null ) {

            if ( logger.isDebugEnabled() ) {
                logger.debug( "No cache implementation set.  Checking cacheProvider...");
            }

            CacheProvider cacheProvider = getAuthorizationInfoCacheProvider();

            if ( cacheProvider != null ) {
                String cacheName = getName() + authorizationInfoCachePostfix;
                if ( logger.isDebugEnabled() ) {
                    logger.debug( "CacheProvider [" + cacheProvider + "] set.  Building " +
                                  "authorizationInfo cache named [" + cacheName + "]");
                }
                cache = cacheProvider.buildCache( cacheName );
                setAuthorizationInfoCache( cache );
            } else {
                if ( logger.isInfoEnabled() ) {
                    logger.info( "No cache or cacheProvider set.  authorizationInfo caching is " +
                            "disabled for realm [" + getName() + "]" );
                }
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug( "authorizationInfo for realm [" + getName() + "] will be cached " +
                        "using cache [" + cache + "]" );
            }
        }

        onInit();
    }

    protected void onInit(){}

    /**
     * Destroys this realm by destroying the underlying caches.
     */
    public void destroy() {
        if( authorizationInfoCache != null ) {
            if (logger.isDebugEnabled()) {
                logger.debug("Destroying authorization info cache for realm [" + getName() + "]");
            }
            authorizationInfoCache.destroy();
        }
    }


    /**
     * <p>Implements the template pattern to retrieve cached authorization information if configured to do so.
     * Subclasses should implement the {@link #doGetAuthorizationInfo(java.security.Principal)} method
     * to return the authorization informatino for the given principal.</p>
     *
     * <p>If caching is enabled, the authorization information is retrieved from a cache if it is cached, otherwise the
     * {@link #doGetAuthorizationInfo(java.security.Principal)} method is called to retrieve the authorization
     * information and the result is cached.</p>
     *
     * @param principal the principal whose authorization information is being retrieved.
     * @return the authorization information associated with this princpal.
     */
    protected final AuthorizationInfo getAuthorizationInfo(Principal principal) {
        AuthorizationInfo info = null;

        if (logger.isDebugEnabled()) {
            logger.debug("Retrieving authorization information for principal [" + principal + "]");
        }

        if( principal == null ) {
            throw new AuthorizationException( "Authorization information cannot be retrieved for null principals." );
        }

        if( authorizationInfoCache != null ) {

            if (logger.isTraceEnabled()) {
                logger.trace("Attempting to retrieve authorization information from cache.");
            }

            info = (AuthorizationInfo) authorizationInfoCache.get( principal );

            if (logger.isTraceEnabled()) {
                if( info == null ) {
                    logger.trace( "No authorization info found in cache for principal [" + principal + "]" );
                } else {
                    logger.trace( "Authorization info found in cache for principal [" + principal + "]" );
                }
            }

        }

        if( info == null ) {

            // Call template method if authorization info was not found in a cache
            info = doGetAuthorizationInfo( principal );

            // If the info is not null and the cache has been created, then cache the info.
            if( info != null && authorizationInfoCache != null ) {

                if (logger.isTraceEnabled()) {
                    logger.trace("Storing authorization info for [" + principal + "] in cache." );
                }

                authorizationInfoCache.put( principal, info );
            }
        }

        return info;
    }


    /**
     * Template-pattern method to be implemented by subclasses to retrieve the authorization information
     * for the given principal.
     * @param principal the principal whose authorization information should be retrieved.
     * @return the authorization information associated with this principal.
     */
    protected abstract AuthorizationInfo doGetAuthorizationInfo(Principal principal);

}