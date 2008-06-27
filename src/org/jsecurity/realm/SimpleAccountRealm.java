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
import org.jsecurity.subject.PrincipalCollection;
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

    public void afterRoleCacheSet() {
    }

    protected void initRoleCache() {
        CacheManager manager = getCacheManager();

        if (manager == null) {
            manager = new HashtableCacheManager();
            setCacheManager(manager);
        }

        if (getAccountCache() == null) {
            initAccountCache();
        }

        String roleCacheName = getRoleCacheName();
        if (roleCacheName == null) {
            roleCacheName = getName() + DEFAULT_ROLE_CACHE_POSTFIX;
            setRoleCacheName(roleCacheName);
        }
        Cache roleCache = manager.getCache(roleCacheName);
        setRoleCache(roleCache);

        userAndRoleCachesCreated();
    }

    protected SimpleAuthorizingAccount getUser(String username) {
        return (SimpleAuthorizingAccount) getAccountCache().get(username);
    }

    protected void add(SimpleAuthorizingAccount user) {
        Object key = getAccountCacheKey(user.getPrincipals());
        getAccountCache().put(key, user);
    }

    protected SimpleRole getRole(String rolename) {
        return (SimpleRole) roleCache.get(rolename);
    }

    protected void add(SimpleRole role) {
        roleCache.put(role.getName(), role);
    }

    protected static Set<String> toSet(String delimited, String delimiter) {
        if (delimited == null || delimited.trim().equals("")) {
            return null;
        }

        Set<String> values = new HashSet<String>();
        String[] rolenamesArray = delimited.split(delimiter);
        for (String s : rolenamesArray) {
            String trimmed = s.trim();
            if (trimmed.length() > 0) {
                values.add(trimmed);
            }
        }

        return values;
    }

    protected void userAndRoleCachesCreated() {
    }

    protected Account doGetAccount(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        return (SimpleAuthorizingAccount) getAccountCache().get(upToken.getUsername());
    }

    protected AuthorizingAccount doGetAccount(PrincipalCollection principals) {
        return (SimpleAuthorizingAccount) getAccountCache().get(getAccountCacheKey(principals));
    }

    protected Object getAccountCacheKey(PrincipalCollection principals) {
        return principals.fromRealm(getName()).iterator().next(); //returns the username
    }
}