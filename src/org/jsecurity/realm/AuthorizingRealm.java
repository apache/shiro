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
public abstract class AuthorizingRealm extends AuthenticatingRealm implements Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * The default postfix appended to the realm name for caching AuthorizingAccounts.
     */
    private static final String DEFAULT_ACCOUNT_CACHE_POSTFIX = ".accounts";

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

    /**
     * The postfix appended to the realm name used to create the name of the authorization cache.
     */
    private String accountCachePostfix = DEFAULT_ACCOUNT_CACHE_POSTFIX;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AuthorizingRealm() {
        super();
    }

    public AuthorizingRealm(String name) {
        super(name);
    }

    public AuthorizingRealm(String name, CacheProvider cacheProvider) {
        super(name, cacheProvider);
    }

    public AuthorizingRealm(String name, CredentialsMatcher matcher) {
        super(name, matcher);
    }

    public AuthorizingRealm(String name, CacheProvider cacheProvider, CredentialsMatcher matcher) {
        super(name, cacheProvider, matcher);
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

    public void setAccountCachePostfix(String accountCachePostfix) {
        this.accountCachePostfix = accountCachePostfix;
    }

    public String getAccountCachePostfix() {
        return accountCachePostfix;
    }

    public void setAccountCache(Cache accountCache) {
        this.accountCache = accountCache;
    }

    public Cache getAccountCache() {
        return this.accountCache;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    /**
     * Initializes this realm and potentially enables a cache, depending on configuration.
     * <p/>
     * <p>When this method is called, the following logic is executed:
     * <ol>
     * <li>If the {@link #setAccountCache cache} property has been set, it will be
     * used to cache the Account objects returned from {@link #getAccount getAccount}
     * method invocations.
     * All future calls to <tt>getAccount</tt> will attempt to use this Account cache first
     * to alleviate any potentially unnecessary calls to an underlying data store.</li>
     * <li>If the {@link # setAccountCache cache} property has <b>not</b> been set,
     * the {@link #setCacheProvider cacheProvider} property will be checked.
     * If a <tt>cacheProvider</tt> has been set, it will be used to create an Account
     * <tt>cache</tt>, and this newly created cache which will be used as specified in #1.</li>
     * <li>If neither the {@link # setAccountCache (org.jsecurity.cache.Cache) cache}
     * or {@link #setCacheProvider (org.jsecurity.cache.CacheProvider) cacheProvider}
     * properties are set, caching will be disabled and Account lookups will be delegated to
     * subclass implementations for each authorization check.</li>
     * </ol>
     */
    public final void init() {
        if (log.isTraceEnabled()) {
            log.trace("Initializing caches for realm [" + getName() + "]");
        }

        if (isAccountCacheEnabled()) {

            Cache cache = getAccountCache();

            if (cache == null) {

                if (log.isDebugEnabled()) {
                    log.debug("No cache implementation set.  Checking cacheProvider...");
                }

                CacheProvider cacheProvider = getCacheProvider();

                if (cacheProvider != null) {
                    String cacheName = getName() + getAccountCachePostfix();
                    if (log.isDebugEnabled()) {
                        log.debug("CacheProvider [" + cacheProvider + "] set.  Building " +
                                "authorizationInfo cache named [" + cacheName + "]");
                    }
                    cache = cacheProvider.buildCache(cacheName);
                    setAccountCache(cache);
                } else {
                    if (log.isInfoEnabled()) {
                        log.info("No cache or cacheProvider properties have been set.  AuthorizingAccount caching is " +
                                "disabled for realm [" + getName() + "]");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("AuthorizingAccount for realm [" + getName() + "] will be cached " +
                            "using cache [" + cache + "]");
                }
            }

        }

        onInit();
    }

    /**
     * Template method that subclasses can override for custom initialization behavior.  The default
     * implementation does nothing.
     */
    protected void onInit() {
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
     * <p>Retrieves Account information from underlying data store.  If this implementation has caching enabled, the
     * returned Account objects will be cached before the method returns and subsequent calls will check the
     * cache first before accesing the data store.
     * <p/>
     * <p>Subclasses must implement the {@link #doGetAccount(Object)} method to access the data store in the event
     * that caching is disabled or there is a cache miss.
     *
     * @param principal the primary identifying principal of the Account that should be retrieved.
     * @return the Account associated with this princpal.
     */
    protected Account getAccount(Object principal) {
        Account account = null;

        if (log.isDebugEnabled()) {
            log.debug("Retrieving Account for principal [" + principal + "]");
        }

        if (principal == null) {
            throw new AuthorizationException("Accounts cannot be retrieved from null principals.");
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

    protected void assertNotNullAccount(Object subjectPrincipal, Account account) {
        if (account == null) {
            throw new MissingAccountException("No Account found for Subject principal [" +
                    subjectPrincipal + "] in realm [" + getName() + "]");
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
            throw new UnsupportedAuthorizationException(msg);
        }
    }

    protected AuthorizingAccount getAuthorizingAccount(Object principal) {
        Account account = getAccount(principal);
        assertNotNullAccount(principal, account);
        assertAuthorizingAccount(account);
        return (AuthorizingAccount) account;
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
        return isPermitted( subjectIdentifier, perms );
    }

    public boolean[] isPermitted(Object principal, List<Permission> permissions) {
        AuthorizingAccount account = getAuthorizingAccount(principal);
        return account.isPermitted( permissions );
    }

    public boolean isPermittedAll(Object subjectIdentifier, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            Collection<Permission> perms = new ArrayList<Permission>(permissions.length);
            for (String permString : permissions) {
                perms.add(getPermissionResolver().resolvePermission(permString));
            }
            return isPermittedAll(subjectIdentifier, perms );
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
}
