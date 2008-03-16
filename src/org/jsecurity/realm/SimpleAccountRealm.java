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
package org.jsecurity.realm;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.authz.SimpleRole;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.HashtableCacheManager;
import org.jsecurity.util.Initializable;

import java.util.HashSet;
import java.util.Set;

/**
 * <p>A simple implementation of the {@link org.jsecurity.realm.Realm Realm} interface that
 * uses a set of configured user accounts and roles to support authentication and authorization.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and associated with users.</p>
 *
 * <p>User accounts and roles are stored in two {@link Cache cache}s, so it is the Cache manager implementation that
 * determines if this class stores all data in memory or spools to disk or clusters it, etc based on the
 * Caches it creates.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SimpleAccountRealm extends AuthorizingRealm implements Initializable {

    /**
     * The default postfix appended to the Role cache name.
     */
    private static final String DEFAULT_ROLE_CACHE_POSTFIX = "-roles";
    private static int INSTANCE_COUNT = 0;

    //parent class already has the user account cache, we just need to add a role cache:
    protected Cache roleCache = null;
    protected String roleCacheName;

    public SimpleAccountRealm() {
    }

    public Cache getRoleCache() {
        return roleCache;
    }

    public void setRoleCache(Cache roleCache) {
        this.roleCache = roleCache;
    }

    public String getRoleCacheName() {
        return roleCacheName;
    }

    public void setRoleCacheName(String roleCacheName) {
        this.roleCacheName = roleCacheName;
    }

    public void afterAccountCacheSet() {
        initRoleCache();
        afterRoleCacheSet();
    }

    public void afterRoleCacheSet(){}

    protected void initRoleCache() {
        CacheManager manager = getCacheManager();

        if ( manager == null ) {
            manager = new HashtableCacheManager();
            setCacheManager(manager);
        }

        if ( getAccountCache() == null ) {
            initAccountCache();
        }

        String roleCacheName = getRoleCacheName();
        if ( roleCacheName == null ) {
            roleCacheName = getClass().getName() + "-" + INSTANCE_COUNT++ + DEFAULT_ROLE_CACHE_POSTFIX;
            setRoleCacheName( roleCacheName );
        }
        Cache roleCache = manager.getCache( roleCacheName );
        setRoleCache(roleCache);

        userAndRoleCachesCreated();
    }

    protected SimpleAuthorizingAccount getUser( String username ) {
        return (SimpleAuthorizingAccount)getAccountCache().get( username );
    }

    protected void add( SimpleAuthorizingAccount user ) {
        getAccountCache().put( user.getPrincipal(), user );
    }

    protected SimpleRole getRole( String rolename ) {
        return (SimpleRole)roleCache.get( rolename );
    }

    protected void add( SimpleRole role ) {
        roleCache.put( role.getName(), role );
    }

    protected static Set<String> toSet( String delimited, String delimiter ) {
        if ( delimited == null || delimited.trim().equals( "" ) ) {
            return null;
        }

        Set<String> values = new HashSet<String>();
        String[] rolenamesArray = delimited.split( delimiter );
        for ( String s : rolenamesArray ) {
            String trimmed = s.trim();
            if ( trimmed.length() > 0 ) {
                values.add( trimmed );
            }
        }

        return values;
    }

    protected void userAndRoleCachesCreated(){}

    protected Account doGetAccount( AuthenticationToken token ) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;
        return doGetAccount( upToken.getUsername() );
    }

    protected AuthorizingAccount doGetAccount(Object principal) {
        return (SimpleAuthorizingAccount)getAccountCache().get(principal);
    }
}