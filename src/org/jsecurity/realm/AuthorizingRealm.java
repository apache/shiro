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
package org.jsecurity.realm;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.*;
import org.jsecurity.authz.permission.PermissionResolver;
import org.jsecurity.authz.permission.PermissionResolverAware;
import org.jsecurity.authz.permission.WildcardPermissionResolver;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.util.Initializable;

import java.util.*;

/**
 * An <tt>AuthorizingRealm</tt> extends the <tt>AuthenticatingRealm</tt>'s capabilities by adding Authorization
 * (access control) support.
 *
 * <p>This implementation will perform all role and permission checks automatically (and subclasses do not have to
 * write this logic) as long as the
 * {@link #getAuthorizationInfo(org.jsecurity.subject.PrincipalCollection)} method returns an
 * {@link AuthorizationInfo}.  Please see that method's JavaDoc for an in-depth explanation.
 *
 * <p>If you find that you do not want to utilize the {@link AuthorizationInfo AuthorizationInfo} construct,
 * you are of course free to subclass the {@link AuthenticatingRealm AuthenticatingRealm} directly instead and
 * implement the remaining Realm interface methods directly.  You might do this if you want have better control
 * over how the Role and Permission checks occur for your specific data source.  However, using AuthorizationInfo
 * (and its default implementation {@link SimpleAuthorizationInfo SimpleAuthorizationInfo}) is sufficient in the large
 * majority of Realm cases.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @see SimpleAuthorizationInfo
 * @since 0.2
 */
public abstract class AuthorizingRealm extends AuthenticatingRealm implements Initializable, PermissionResolverAware {

    //TODO - complete JavaDoc

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final Log log = LogFactory.getLog(AuthorizingRealm.class);

    /**
     * The default postfix appended to the realm name for caching AuthorizationInfos.
     */
    private static final String DEFAULT_AUTHORIZATION_CACHE_POSTFIX = "-authorization";

    private static int INSTANCE_COUNT = 0;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The cache used by this realm to store AuthorizationInfos associated with individual Subject principals.
     */
    private Cache authorizationCache = null;
    private String authorizationCacheName = null;

    private PermissionResolver permissionResolver = new WildcardPermissionResolver();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthorizingRealm() {
    }

    public AuthorizingRealm(CacheManager cacheManager) {
        super(cacheManager);
    }

    public AuthorizingRealm(CredentialsMatcher matcher) {
        super(matcher);
    }

    public AuthorizingRealm(CacheManager cacheManager, CredentialsMatcher matcher) {
        super(cacheManager, matcher);
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAuthorizationCache(Cache authorizationCache) {
        this.authorizationCache = authorizationCache;
        if (this.authorizationCache != null) {
            afterAuthorizationCacheSet();
        }
    }

    public Cache getAuthorizationCache() {
        return this.authorizationCache;
    }

    public String getAuthorizationCacheName() {
        return authorizationCacheName;
    }

    public void setAuthorizationCacheName(String authorizationCacheName) {
        this.authorizationCacheName = authorizationCacheName;
    }

    public PermissionResolver getPermissionResolver() {
        return permissionResolver;
    }

    public void setPermissionResolver(PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Initializes this realm and potentially enables a cache, depending on configuration.
     *
     * <p>When this method is called, the following logic is executed:
     * <ol>
     * <li>If the {@link #setAuthorizationCache cache} property has been set, it will be
     * used to cache the AuthorizationInfo objects returned from {@link #getAuthorizationInfo}
     * method invocations.
     * All future calls to <tt>getAuthorizationInfo</tt> will attempt to use this cache first
     * to alleviate any potentially unnecessary calls to an underlying data store.</li>
     * <li>If the {@link #setAuthorizationCache cache} property has <b>not</b> been set,
     * the {@link #setCacheManager cacheManager} property will be checked.
     * If a <tt>cacheManager</tt> has been set, it will be used to create an authorization
     * <tt>cache</tt>, and this newly created cache which will be used as specified in #1.</li>
     * <li>If neither the {@link #setAuthorizationCache (org.jsecurity.cache.Cache) cache}
     * or {@link #setCacheManager(org.jsecurity.cache.CacheManager) cacheManager}
     * properties are set, caching will be disabled and authorization lookups will be delegated to
     * subclass implementations for each authorization check.</li>
     * </ol>
     */
    public final void init() {
        initAuthorizationCache();
    }

    protected void afterCacheManagerSet() {
        this.authorizationCache = null;
        initAuthorizationCache();
    }

    protected void afterAuthorizationCacheSet() {
    }

    public void initAuthorizationCache() {
        if (log.isTraceEnabled()) {
            log.trace("Initializing authorization cache.");
        }

        Cache cache = getAuthorizationCache();

        if (cache == null) {

            if (log.isDebugEnabled()) {
                log.debug("No cache implementation set.  Checking cacheManager...");
            }

            CacheManager cacheManager = getCacheManager();

            if (cacheManager != null) {
                String cacheName = getAuthorizationCacheName();
                if (cacheName == null) {
                    //Simple default in case they didn't provide one:
                    cacheName = getClass().getName() + "-" + INSTANCE_COUNT++ + DEFAULT_AUTHORIZATION_CACHE_POSTFIX;
                    setAuthorizationCacheName(cacheName);
                }
                if (log.isDebugEnabled()) {
                    log.debug("CacheManager [" + cacheManager + "] has been configured.  Building " +
                            "authorization cache named [" + cacheName + "]");
                }
                cache = cacheManager.getCache(cacheName);
                setAuthorizationCache(cache);
            } else {
                if (log.isInfoEnabled()) {
                    log.info("No cache or cacheManager properties have been set.  Authorization caching is " +
                            "disabled.");
                }
            }
        }
    }


    /**
     * Returns an account's authorization-specific information for the specified <code>principals</code>,
     * or <tt>null</tt> if no account could be found.  The resulting <code>AuthorizationInfo</code> object is used
     * by the other method implementations in this class to automatically perform access control checks for the
     * corresponding <code>Subject</code>.
     *
     * <p>This implementation obtains the actual <code>AuthorizationInfo</code> object from the subclass's
     * implementation of
     * {@link #doGetAuthorizationInfo(org.jsecurity.subject.PrincipalCollection) doGetAuthorizationInfo}, and then
     * caches it for efficient reuse if caching is enabled (see below).
     *
     * <p>Invocations of this method should be thought of as completely orthogonal to acquiring
     * {@link #getAuthenticationInfo(org.jsecurity.authc.AuthenticationToken) authenticationInfo}, since either could
     * occur in any order.
     *
     * <p>For example, in &quot;Remember Me&quot; scenarios, the user identity is remembered (and
     * assumed) for their current session and an authentication attempt during that session might never occur.
     * But because their identity would be remembered, that is sufficient enough information to call this method to
     * execute any necessary authorization checks.  For this reason, authentication and authorization should be
     * loosely coupled and not depend on each other.
     *
     * <h4>Caching</h4>
     *
     * <p>The <code>AuthorizationInfo</code> values returned from this method are cached for performant reuse
     * if caching is enabled.  Caching is enabled automatically when a <code>CacheManager</code> has been
     * {@link #setCacheManager injected} and then the realm is {@link #init initialized}.  It can also be enabled by explictly
     * calling {@link #initAuthorizationCache() initAuthorizationCache()}.
     *
     * <p>If caching is enabled, the authorization cache will be checked first and if found, will return the cached
     * <code>AuthorizationInfo</code> immediately.  If caching is disabled, or there is a cache miss from the cache
     * lookup, the authorization info will be looked up from the underlying data store via the
     * {@link #doGetAuthorizationInfo(PrincipalCollection)} method, which must be implemented by subclasses.
     *
     * <p><b>Please note:</b>  If caching is enabled and if any authorization data for an account is changed at
     * runtime, such as adding or removing roles and/or permissions, the subclass imlementation should clear the
     * cached AuthorizationInfo for that account via the
     * {@link #clearCachedAuthorizationInfo(org.jsecurity.subject.PrincipalCollection) clearCachedAuthorizationInfo}
     * method.  This ensures that the next call to <code>getAuthorizationInfo(PrincipalCollection)</code> will
     * acquire the account's fresh authorization data, where it will then be cached for efficient reuse.  This
     * ensures that stale authorization data will not be reused.
     *
     * @param principals the corresponding Subject's identifying principals with which to look up the Subject's
     *                   <code>AuthorizationInfo</code>.
     * @return the authorization information for the account associated with the specified <code>principals</code>,
     *         or <tt>null</tt> if no account could be found.
     */
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        if (principals == null) {
            return null;
        }

        AuthorizationInfo info = null;

        if (log.isTraceEnabled()) {
            log.trace("Retrieving AuthorizationInfo for principals [" + principals + "]");
        }

        Cache authzCache = getAuthorizationCache();
        if (authzCache != null) {
            if (log.isTraceEnabled()) {
                log.trace("Attempting to retrieve the AuthorizationIfno from cache.");
            }
            Object key = getAuthorizationCacheKey(principals);
            info = (AuthorizationInfo) authzCache.get(key);
            if (log.isTraceEnabled()) {
                if (info == null) {
                    log.trace("No AuthorizationInfo found in cache for principals [" + principals + "]");
                } else {
                    log.trace("AuthorizationInfo found in cache for principals [" + principals + "]");
                }
            }
        }


        if (info == null) {
            // Call template method if tbe info was not found in a cache
            info = doGetAuthorizationInfo(principals);
            // If the info is not null and the cache has been created, then cache the authorization info.
            if (info != null && authzCache != null) {
                if (log.isTraceEnabled()) {
                    log.trace("Caching authorization info for principals: [" + principals + "].");
                }
                Object key = getAuthorizationCacheKey(principals);
                authzCache.put(key, info);
            }
        }

        return info;
    }

    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        return principals;
    }

    /**
     * Clears out the AuthorizationInfo cache entry for the specified account.
     * <p/>
     * This method is provided as a convenience to subclasses so they can invalidate a cache entry when they
     * change an account's authorization data (add/remove roles or permissions) during runtime.  Because an account's
     * AuthorizationInfo can be cached, there needs to be a way to invalidate the cache for only that account so that
     * subsequent authorization operations don't used the (old) cached value if account data changes.
     * <p/>
     * After this method is called, the next authorization check for that same account will result in a call to
     * {@link #getAuthorizationInfo(org.jsecurity.subject.PrincipalCollection) getAuthorizationInfo}, and the
     * resulting return value will be cached before being returned so it can be reused for later authorization checks.
     *
     * @param principals the principals of the account for which to clear the cached AuthorizationInfo.
     */
    protected void clearCachedAuthorizationInfo(PrincipalCollection principals) {
        if ( principals == null ) {
            return;
        }

        Cache cache = getAuthorizationCache();
        //cache instance will be non-null if caching is enabled:
        if (cache != null) {
            Object key = getAuthorizationCacheKey(principals);
            cache.remove(key);
        }
    }

    /**
     * Retrieves the AuthorizationInfo for the given principals from the underlying data store.  When returning
     * an instance from this method, you might want to consider using an instance of
     * {@link SimpleAuthorizationInfo SimpleAuthorizationInfo}, as it is suitable in most cases.
     *
     * @param principals the primary identifying principals of the AuthorizationInfo that should be retrieved.
     * @return the AuthorizationInfo associated with this principals.
     * @see SimpleAuthorizationInfo
     */
    protected abstract AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals);

    @SuppressWarnings({"unchecked"})
    private Collection<Permission> getPermissions(AuthorizationInfo info) {
        Set<Permission> permissions = new HashSet<Permission>();

        if (info != null) {
            if (info.getObjectPermissions() != null) {
                permissions.addAll(info.getObjectPermissions());
            }

            if (info.getStringPermissions() != null) {
                for (String strPermission : info.getStringPermissions()) {
                    Permission permission = getPermissionResolver().resolvePermission(strPermission);
                    permissions.add(permission);
                }
            }
        }

        if (permissions.isEmpty()) {
            return Collections.EMPTY_SET;
        } else {
            return Collections.unmodifiableSet(permissions);
        }
    }

    public boolean isPermitted(PrincipalCollection principals, String permission) {
        Permission p = getPermissionResolver().resolvePermission(permission);
        return isPermitted(principals, p);
    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        AuthorizationInfo info = getAuthorizationInfo(principals);
        return isPermitted(permission, info);
    }

    @SuppressWarnings("deprecation")
    private boolean isPermitted(Permission permission, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            return ((AuthorizingAccount) info).isPermitted(permission);
        }

        Collection<Permission> perms = getPermissions(info);
        if (perms != null && !perms.isEmpty()) {
            for (Permission perm : perms) {
                if (perm.implies(permission)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean[] isPermitted(PrincipalCollection subjectIdentifier, String... permissions) {
        List<Permission> perms = new ArrayList<Permission>(permissions.length);
        for (String permString : permissions) {
            perms.add(getPermissionResolver().resolvePermission(permString));
        }
        return isPermitted(subjectIdentifier, perms);
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo(principals);
        return isPermitted(permissions, info);
    }

    @SuppressWarnings("deprecation")
    protected boolean[] isPermitted(List<Permission> permissions, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            return ((AuthorizingAccount) info).isPermitted(permissions);
        }

        boolean[] result;
        if (permissions != null && !permissions.isEmpty()) {
            int size = permissions.size();
            result = new boolean[size];
            int i = 0;
            for (Permission p : permissions) {
                result[i++] = isPermitted(p, info);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean isPermittedAll(PrincipalCollection subjectIdentifier, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            Collection<Permission> perms = new ArrayList<Permission>(permissions.length);
            for (String permString : permissions) {
                perms.add(getPermissionResolver().resolvePermission(permString));
            }
            return isPermittedAll(subjectIdentifier, perms);
        }
        return false;
    }

    public boolean isPermittedAll(PrincipalCollection principal, Collection<Permission> permissions) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        return info != null && isPermittedAll(permissions, info);
    }

    @SuppressWarnings("deprecation")
    protected boolean isPermittedAll(Collection<Permission> permissions, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            return ((AuthorizingAccount) info).isPermittedAll(permissions);
        }

        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                if (!isPermitted(p, info)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(PrincipalCollection subjectIdentifier, String permission) throws AuthorizationException {
        Permission p = getPermissionResolver().resolvePermission(permission);
        checkPermission(subjectIdentifier, p);
    }

    public void checkPermission(PrincipalCollection principal, Permission permission) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        checkPermission(permission, info);
    }

    @SuppressWarnings("deprecation")
    protected void checkPermission(Permission permission, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            ((AuthorizingAccount) info).checkPermission(permission);
        } else {
            if (!isPermitted(permission, info)) {
                String msg = "User is not permitted [" + permission + "]";
                throw new UnauthorizedException(msg);
            }
        }
    }

    public void checkPermissions(PrincipalCollection subjectIdentifier, String... permissions) throws AuthorizationException {
        if (permissions != null) {
            for (String permString : permissions) {
                checkPermission(subjectIdentifier, permString);
            }
        }
    }

    public void checkPermissions(PrincipalCollection principal, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        checkPermissions(permissions, info);
    }

    @SuppressWarnings("deprecation")
    protected void checkPermissions(Collection<Permission> permissions, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            ((AuthorizingAccount) info).checkPermissions(permissions);
        } else {
            if (permissions != null && !permissions.isEmpty()) {
                for (Permission p : permissions) {
                    checkPermission(p, info);
                }
            }
        }
    }

    public boolean hasRole(PrincipalCollection principal, String roleIdentifier) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        return hasRole(roleIdentifier, info);
    }

    @SuppressWarnings("deprecation")
    protected boolean hasRole(String roleIdentifier, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            return ((AuthorizingAccount) info).hasRole(roleIdentifier);
        }
        return info != null && info.getRoles() != null && info.getRoles().contains(roleIdentifier);
    }

    public boolean[] hasRoles(PrincipalCollection principal, List<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        boolean[] result = new boolean[roleIdentifiers != null ? roleIdentifiers.size() : 0];
        if (info != null) {
            result = hasRoles(roleIdentifiers, info);
        }
        return result;
    }

    @SuppressWarnings("deprecation")
    protected boolean[] hasRoles(List<String> roleIdentifiers, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            return ((AuthorizingAccount) info).hasRoles(roleIdentifiers);
        }

        boolean[] result;
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            int size = roleIdentifiers.size();
            result = new boolean[size];
            int i = 0;
            for (String roleName : roleIdentifiers) {
                result[i++] = hasRole(roleName, info);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean hasAllRoles(PrincipalCollection principal, Collection<String> roleIdentifiers) {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        return info != null && hasAllRoles(roleIdentifiers, info);
    }

    @SuppressWarnings("deprecation")
    private boolean hasAllRoles(Collection<String> roleIdentifiers, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            return ((AuthorizingAccount) info).hasAllRoles(roleIdentifiers);
        }

        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            for (String roleName : roleIdentifiers) {
                if (!hasRole(roleName, info)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkRole(PrincipalCollection principal, String role) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        checkRole(role, info);
    }

    @SuppressWarnings("deprecation")
    protected void checkRole(String role, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            ((AuthorizingAccount) info).checkRole(role);
        } else {
            if (!hasRole(role, info)) {
                String msg = "User does not have role [" + role + "]";
                throw new UnauthorizedException(msg);
            }
        }
    }

    public void checkRoles(PrincipalCollection principal, Collection<String> roles) throws AuthorizationException {
        AuthorizationInfo info = getAuthorizationInfo(principal);
        checkRoles(roles, info);
    }

    @SuppressWarnings("deprecation")
    protected void checkRoles(Collection<String> roles, AuthorizationInfo info) {
        //todo Remove this once AuthorizingAccount class is deleted
        if (info instanceof AuthorizingAccount) {
            ((AuthorizingAccount) info).checkRoles(roles);
        } else {
            if (roles != null && !roles.isEmpty()) {
                for (String roleName : roles) {
                    checkRole(roleName, info);
                }
            }
        }
    }

    /**
     * If authorization caching is enabled, this will remove the AuthorizationInfo from the cache.
     * Subclasses are free to override for additional behavior, but be sure to call <tt>super.onLogout</tt>
     * to ensure cache cleanup.
     *
     * @param principals the application-specific Subject/user identifier.
     */
    public void onLogout(PrincipalCollection principals) {
        clearCachedAuthorizationInfo(principals);
    }
}
