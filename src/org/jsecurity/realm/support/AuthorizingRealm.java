/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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

import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.NoAuthorizationInfoFoundException;
import org.jsecurity.authz.Permission;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.LifecycleUtils;

import java.util.Collection;
import java.util.List;

/**
 * An <tt>AuthorizingRealm</tt> extends the <tt>AuthenticatingRealm</tt>'s capabilities by adding authorization
 * (access control) support.
 *
 * @since 0.2
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public abstract class AuthorizingRealm extends AuthenticatingRealm implements Initializable, Destroyable {

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
     * Determines whether or not caching is enabled for authorization info.  Caching is enabled by default, but
     * realms that access authorization info in memory may wish to disable caching.
     */
    private boolean authorizationInfoCacheEnabled = true;

    /**
     * The cache used by this realm to store authorization information associated with individual
     * principals.
     */
    private Cache authorizationInfoCache = null;

    /**
     * The postfix appended to the realm name used to create the name of the authorization cache.
     */
    private String authorizationInfoCachePostfix = DEFAULT_AUTHORIZATION_INFO_CACHE_POSTFIX ;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthorizingRealm() {
        super();
    }

    public AuthorizingRealm( String name ) {
        super( name );
    }

    public AuthorizingRealm( String name, CacheProvider cacheProvider ) {
        super( name, cacheProvider );
    }

    public AuthorizingRealm( String name, CredentialsMatcher matcher ) {
        super( name, matcher );
    }

    public AuthorizingRealm( String name, CacheProvider cacheProvider, CredentialsMatcher matcher ) {
        super( name, cacheProvider, matcher );
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public void setAuthorizationInfoCacheEnabled(boolean authorizationInfoCacheEnabled) {
        this.authorizationInfoCacheEnabled = authorizationInfoCacheEnabled;
    }

    public void setAuthorizationInfoCachePostfix(String authorizationInfoCachePostfix) {
        this.authorizationInfoCachePostfix = authorizationInfoCachePostfix;
    }

    public void setAuthorizationInfoCache(Cache authorizationInfoCache) {
        this.authorizationInfoCache = authorizationInfoCache;
    }

    public Cache getAuthorizationInfoCache() {
        return this.authorizationInfoCache;
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
     *       the {@link #setCacheProvider cacheProvider} property will be checked.
     *       If a <tt>cacheProvider</tt> has been set, it will be used to create a
     *       <tt>cache</tt>, and this newly created cache which will be used as specified in #1.</li>
     *   <li>If neither the {@link #setAuthorizationInfoCache(org.jsecurity.cache.Cache) cache}
     *       or {@link #setCacheProvider (org.jsecurity.cache.CacheProvider) cacheProvider}
     *       properties are set, caching will be disabled.</li>
     * </ol>
     */
    public final void init() {
        if (log.isTraceEnabled()) {
            log.trace("Initializing caches for realm [" + getName() + "]");
        }

        if( authorizationInfoCacheEnabled ) {

            Cache cache = getAuthorizationInfoCache();

            if ( cache == null ) {

                if ( log.isDebugEnabled() ) {
                    log.debug( "No cache implementation set.  Checking cacheProvider...");
                }

                CacheProvider cacheProvider = getCacheProvider();

                if ( cacheProvider != null ) {
                    String cacheName = getName() + authorizationInfoCachePostfix;
                    if ( log.isDebugEnabled() ) {
                        log.debug( "CacheProvider [" + cacheProvider + "] set.  Building " +
                                      "authorizationInfo cache named [" + cacheName + "]");
                    }
                    cache = cacheProvider.buildCache( cacheName );
                    setAuthorizationInfoCache( cache );
                } else {
                    if ( log.isInfoEnabled() ) {
                        log.info( "No cache or cacheProvider properties have been set.  AuthorizationInfo caching is " +
                                "disabled for realm [" + getName() + "]" );
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug( "AuthorizationInfo for realm [" + getName() + "] will be cached " +
                            "using cache [" + cache + "]" );
                }
            }

        }

        onInit();
    }

    /**
     * Template method that subclasses can override for custom initialization behavior.  The default
     * implementation does nothing.
     */
    protected void onInit(){}

    /**
     * Cleans up this realm's cache.
     */
    public void destroy() {
        LifecycleUtils.destroy( authorizationInfoCache );
        this.authorizationInfoCache = null;
    }

    /**
     * Template-pattern method to be implemented by subclasses to retrieve the authorization information
     * for the given principal.
     * @param principal the principal whose authorization information should be retrieved.
     * @return the authorization information associated with this principal.
     */
    protected abstract AuthorizationInfo doGetAuthorizationInfo(Object principal);

    /**
     * <p>Implements the template pattern to retrieve cached authorization information if configured to do so.
     * Subclasses should implement the {@link #doGetAuthorizationInfo(Object)} method
     * to return the authorization informatino for the given principal.</p>
     *
     * <p>If caching is enabled, the authorization information is retrieved from a cache if it is cached, otherwise the
     * {@link #doGetAuthorizationInfo(Object)} method is called to retrieve the authorization
     * information and the result is cached.</p>
     *
     * @param principal the principal whose authorization information is being retrieved.
     * @return the authorization information associated with this princpal.
     */
    protected final AuthorizationInfo getAuthorizationInfo( Object principal) {
        AuthorizationInfo info = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authorization information for principal [" + principal + "]");
        }

        if( principal == null ) {
            throw new AuthorizationException( "Authorization information cannot be retrieved for null principals." );
        }

        if( authorizationInfoCache != null ) {

            if (log.isTraceEnabled()) {
                log.trace("Attempting to retrieve authorization information from cache.");
            }

            info = (AuthorizationInfo) authorizationInfoCache.get( principal );

            if (log.isTraceEnabled()) {
                if( info == null ) {
                    log.trace( "No authorization info found in cache for principal [" + principal + "]" );
                } else {
                    log.trace( "Authorization info found in cache for principal [" + principal + "]" );
                }
            }

        }

        if( info == null ) {

            // Call template method if authorization info was not found in a cache
            info = doGetAuthorizationInfo( principal );

            // If the info is not null and the cache has been created, then cache the info.
            if( info != null && authorizationInfoCache != null ) {

                if (log.isTraceEnabled()) {
                    log.trace("Storing authorization info for [" + principal + "] in cache." );
                }

                authorizationInfoCache.put( principal, info );
            }
        }

        return info;
    }


    public boolean hasRole(Object principal, String roleIdentifier) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        return info != null && info.hasRole( roleIdentifier );
    }

    public boolean[] hasRoles(Object principal, List<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        boolean[] result = new boolean[ roleIdentifiers != null ? roleIdentifiers.size() : 0 ];
        if ( info != null ) {
            result = info.hasRoles( roleIdentifiers );
        }
        return result;
    }

    public boolean hasAllRoles(Object principal, Collection<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        return info != null && info.hasAllRoles( roleIdentifiers );
    }

    public boolean isPermitted(Object principal, Permission permission) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        return info != null && info.isPermitted( permission );
    }

    public boolean[] isPermitted(Object principal, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        boolean[] result = new boolean[ permissions != null ? permissions.size() : 0 ];
        if ( info != null ) {
            result = info.isPermitted( permissions );
        }
        return result;
    }

    public boolean isPermittedAll(Object principal, Collection<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        return info != null && info.isPermittedAll( permissions );
    }

    /**
     * Checks the returned authorization information for validity.  The default implementation
     * simply checks that it is not null.
     * @param info the info being checked.
     * @param principal the principal that info was retrieved for.
     */
    protected void checkAuthorizationInfo(AuthorizationInfo info, Object principal) {
        if( info == null ) {
            throw new NoAuthorizationInfoFoundException( "No authorization info found for principal [" + principal + "] in realm [" + getName() + "]" );
        }
    }

    public void checkPermission(Object principal, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkPermission( permission );
    }

    public void checkPermissions(Object principal, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkPermissions( permissions );
    }


    public void checkRole(Object principal, String role) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkRole( role );
    }

    public void checkRoles(Object principal, Collection<String> roles) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo( principal );
        checkAuthorizationInfo( info, principal );
        info.checkRoles( roles );
    }

}
