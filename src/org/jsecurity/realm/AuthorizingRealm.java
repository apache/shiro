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
package org.jsecurity.realm;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.credential.CredentialsMatcher;
import org.jsecurity.authz.*;
import org.jsecurity.authz.permission.PermissionResolver;
import org.jsecurity.authz.permission.PermissionResolverAware;
import org.jsecurity.authz.permission.WildcardPermissionResolver;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.LifecycleUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * An <tt>AuthorizingRealm</tt> extends the <tt>AuthenticatingRealm</tt>'s capabilities by adding Authorization
 * (access control) support via the use of {@link AuthorizingAccount AuthorizingAccount} instances.
 * <p/>
 * <p>This implementation can only support Authorization operations if the subclass implementation's
 * {@link #getAccount(Object) getAccount(principal)} method returns an {@link AuthorizingAccount AuthorizingAccount}.
 * <p>If it does not, subclasses <em>must</em> override all {@link org.jsecurity.authz.Authorizer Authorizer} methods,
 * since the JSecurity default implementations cannot infer Role/Permissino assignments via anything but
 * <tt>AuthorizingAccount</tt> instances.
 * <p/>
 * <p>If your Realm implementation does not want to deal with <tt>AuthorizingAccount</tt> constructs, you are of course
 * free to subclass the {@link AuthorizingRealm AuthorizingRealm} directly and implement the remaining
 * interface methods yourself.  Many people do this if they want to have better control over how the
 * Role and Permission checks occur for their specific data source.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.2
 */
public abstract class AuthorizingRealm extends AuthenticatingRealm implements Initializable, Destroyable, PermissionResolverAware {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * The default postfix appended to the realm name for caching Accounts.
     */
    private static final String DEFAULT_ACCOUNT_CACHE_POSTFIX = ".accounts";

    private static int INSTANCE_COUNT = 0;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Determines whether or not caching is enabled for AuthorizationAccounts.  Caching is enabled by default, but
     * realms that access AuthorizationAccounts in memory, or those that do their own caching, may wish to disable caching.
     */
    private boolean accountCacheEnabled = true;

    /**
     * The cache used by this realm to store Accounts associated with individual Subject principals.
     */
    private Cache accountCache = null;
    private String accountCacheName = null;

    private PermissionResolver permissionResolver = new WildcardPermissionResolver();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthorizingRealm() {
    }

    public AuthorizingRealm(CacheProvider cacheProvider) {
        super(cacheProvider);
    }

    public AuthorizingRealm(CredentialsMatcher matcher) {
        super(matcher);
    }

    public AuthorizingRealm(CacheProvider cacheProvider, CredentialsMatcher matcher) {
        super(cacheProvider, matcher);
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAccountCacheEnabled(boolean accountCacheEnabled) {
        this.accountCacheEnabled = accountCacheEnabled;
    }

    public boolean isAccountCacheEnabled() {
        return this.accountCacheEnabled;
    }

    public void setAccountCache(Cache accountCache) {
        this.accountCache = accountCache;
    }

    public Cache getAccountCache() {
        return this.accountCache;
    }

    public String getAccountCacheName() {
        return accountCacheName;
    }

    public void setAccountCacheName(String accountCacheName) {
        this.accountCacheName = accountCacheName;
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
     * <li>If the {@link #setAccountCache cache} property has been set, it will be
     * used to cache the Account objects returned from {@link #getAccount getAccount}
     * method invocations.
     * All future calls to <tt>getAccount</tt> will attempt to use this Account cache first
     * to alleviate any potentially unnecessary calls to an underlying data store.</li>
     * <li>If the {@link #setAccountCache cache} property has <b>not</b> been set,
     * the {@link #setCacheProvider cacheProvider} property will be checked.
     * If a <tt>cacheProvider</tt> has been set, it will be used to create an Account
     * <tt>cache</tt>, and this newly created cache which will be used as specified in #1.</li>
     * <li>If neither the {@link #setAccountCache (org.jsecurity.cache.Cache) cache}
     * or {@link #setCacheProvider (org.jsecurity.cache.CacheProvider) cacheProvider}
     * properties are set, caching will be disabled and Account lookups will be delegated to
     * subclass implementations for each authorization check.</li>
     * </ol>
     */
    public final void init() {
        if (isAccountCacheEnabled()) {
            initAccountCache();
        }
        afterAccountCacheSet();
    }

    protected void afterAccountCacheSet(){}

    protected void initAccountCache() {
        if (log.isTraceEnabled()) {
            log.trace("Initializing account cache.");
        }

        Cache cache = getAccountCache();

        if (cache == null) {

            if (log.isDebugEnabled()) {
                log.debug("No cache implementation set.  Checking cacheProvider...");
            }

            CacheProvider cacheProvider = getCacheProvider();

            if (cacheProvider != null) {
                String cacheName = getAccountCacheName();
                if (cacheName == null) {
                    //Simple default in case they didn't provide one:
                    cacheName = getClass().getName() + "_" + INSTANCE_COUNT++ + DEFAULT_ACCOUNT_CACHE_POSTFIX;
                }
                if (log.isDebugEnabled()) {
                    log.debug("CacheProvider [" + cacheProvider + "] has been configured.  Building " +
                            "Account cache named [" + cacheName + "]");
                }
                cache = cacheProvider.buildCache(cacheName);
                setAccountCache(cache);
            } else {
                if (log.isInfoEnabled()) {
                    log.info("No cache or cacheProvider properties have been set.  Account caching is " +
                            "disabled.");
                }
            }
        } else {
            cache.clear();
            if (log.isDebugEnabled()) {
                log.debug("Accounts will be cached using cache [" + cache + "]");
            }
        }
    }

    /**
     * Cleans up this realm's cache.
     */
    public void destroy() {
        Cache accountCache = getAccountCache();
        LifecycleUtils.destroy(accountCache);
        this.accountCache = null;
    }

    /**
     * Template-pattern method to be implemented by subclasses to retrieve the Account for the given principal.
     *
     * @param principal the primary identifying principal of the Account that should be retrieved.
     * @return the Account associated with this principal.
     */
    protected abstract AuthorizingAccount doGetAccount(Object principal);

    /**
     * <p>Retrieves Account information for the given account principal.
     *
     * <p>If caching is enabled, the account cache will be checked first and if found, will return the cached account.
     * If caching is disabled, or there is a cache miss from the cache lookup, the Account will be looked up from
     * the underlying data store via the {@link #doGetAccount(Object)} method, which must be implemented by subclasses.
     *
     * <p>If caching is enabled, the retrieved Account from <tt>doGetAccount</tt> will be added to the account cache
     * first and then returned.
     *
     * @param principal the primary identifying principal of the Account that should be retrieved.
     * @return the Account associated with this princpal.
     */
    protected Account getAccount(Object principal) {

        if (principal == null) {
            return null;
        }

        Account account = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving Account for principal [" + principal + "]");
        }

        boolean cacheEnabled = isAccountCacheEnabled();
        Cache accountCache = null;
        if (cacheEnabled) {
            accountCache = getAccountCache();
            if (accountCache != null) {
                if (log.isTraceEnabled()) {
                    log.trace("Attempting to retrieve the Account from cache.");
                }
                account = (Account) accountCache.get(principal);
                if (log.isTraceEnabled()) {
                    if (account == null) {
                        log.trace("No Account found in cache for principal [" + principal + "]");
                    } else {
                        log.trace("Account found in cache for principal [" + principal + "]");
                    }
                }
            }
        }


        if (account == null) {
            // Call template method if tbe Account was not found in a cache
            account = doGetAccount(principal);
            // If the account is not null and the cache has been created, then cache the account.
            if (account != null && accountCache != null) {
                if (log.isTraceEnabled()) {
                    log.trace("Caching Account [" + principal + "].");
                }
                accountCache.put(principal, account);
            }
        }

        return account;
    }

    protected AuthorizingAccount getAuthorizingAccount(Object principal) {
        if (principal == null) {
            throw new AuthorizationException("Specified principal argument is null and authorization checks cannot " +
                    "occur without a known account identity.");
        }
        Account account = getAccount(principal);
        assertNotNullAccount(principal, account);
        assertAuthorizingAccount(account);
        return (AuthorizingAccount) account;
    }

    protected void assertNotNullAccount(Object subjectPrincipal, Account account) {
        if (account == null) {
            throw new MissingAccountException("No Account found for Subject principal [" +
                    subjectPrincipal + "]");
        }
    }

    protected void assertAuthorizingAccount(Account account) {
        if (!(account instanceof AuthorizingAccount)) {
            String msg = "Underlying Account instance [" + account + "] does not implement the " +
                    AuthorizingAccount.class.getName() + " interface.  The JSecurity " +
                    AuthorizingRealm.class.getName() + " class and its default implementations can only provide default " +
                    "authorization (access control) support for Accounts that implement this interface.  If you do not " +
                    "wish to implement this interface, you will need to override all of this Realm's Authorizer methods " +
                    "to perform the authorization check explicitly.\n\nNote that there is nothing wrong with this " +
                    "approach since it often gives finer control of how authorization checks occur, but you would have " +
                    "to override these methods explicitly since JSecurity can't infer your application's security " +
                    "data model.";
            throw new UnsupportedAccountException(msg);
        }
    }


    public boolean isPermitted(Object subjectIdentifier, String permission) {
        Permission p = getPermissionResolver().resolvePermission(permission);
        return isPermitted(subjectIdentifier, p);
    }

    public boolean isPermitted(Object principal, Permission permission) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        return account.isPermitted(permission);
    }

    public boolean[] isPermitted(Object subjectIdentifier, String... permissions) {
        List<Permission> perms = new ArrayList<Permission>(permissions.length);
        for (String permString : permissions) {
            perms.add(getPermissionResolver().resolvePermission(permString));
        }
        return isPermitted(subjectIdentifier, perms);
    }

    public boolean[] isPermitted(Object principal, List<Permission> permissions) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        return account.isPermitted(permissions);
    }

    public boolean isPermittedAll(Object subjectIdentifier, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            Collection<Permission> perms = new ArrayList<Permission>(permissions.length);
            for (String permString : permissions) {
                perms.add(getPermissionResolver().resolvePermission(permString));
            }
            return isPermittedAll(subjectIdentifier, perms);
        }
        return false;
    }

    public boolean isPermittedAll(Object principal, Collection<Permission> permissions) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        return account != null && account.isPermittedAll(permissions);
    }

    public void checkPermission(Object subjectIdentifier, String permission) throws AuthorizationException {
        Permission p = getPermissionResolver().resolvePermission(permission);
        checkPermission(subjectIdentifier, p);
    }

    public void checkPermission(Object principal, Permission permission) throws AuthorizationException {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        account.checkPermission(permission);
    }

    public void checkPermissions(Object subjectIdentifier, String... permissions) throws AuthorizationException {
        if (permissions != null) {
            for (String permString : permissions) {
                checkPermission(subjectIdentifier, permString);
            }
        }
    }

    public void checkPermissions(Object principal, Collection<Permission> permissions) throws AuthorizationException {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        account.checkPermissions(permissions);
    }

    public boolean hasRole(Object principal, String roleIdentifier) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        return account.hasRole(roleIdentifier);
    }

    public boolean[] hasRoles(Object principal, List<String> roleIdentifiers) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        boolean[] result = new boolean[roleIdentifiers != null ? roleIdentifiers.size() : 0];
        if (account != null) {
            result = account.hasRoles(roleIdentifiers);
        }
        return result;
    }

    public boolean hasAllRoles(Object principal, Collection<String> roleIdentifiers) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        return account != null && account.hasAllRoles(roleIdentifiers);
    }

    public void checkRole(Object principal, String role) throws AuthorizationException {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        account.checkRole(role);
    }

    public void checkRoles(Object principal, Collection<String> roles) throws AuthorizationException {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        account.checkRoles(roles);
    }

    /**
     * If account caching is enabled, this will remove the account from the cache.  Subclasses are free to override
     * for additional behavior, but be sure to call <tt>super.onLogout</tt> to ensure cache cleanup.
     *
     * @param accountPrincipal the application-specific Subject/user identifier.
     */
    public void onLogout(Object accountPrincipal) {
        Cache cache = getAccountCache();
        //cache instance will be non-null if caching is enabled:
        if (cache != null && accountPrincipal != null) {
            cache.remove(accountPrincipal);
        }
    }
}
