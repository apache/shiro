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
package org.apache.shiro.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizingAccount;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * <p>A simple implementation of the {@link Realm Realm} interface that
 * uses a set of configured user accounts and roles to support authentication and authorization.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and associated with users.</p>
 * <p/>
 * <p>User accounts and roles are stored in two {@link org.apache.shiro.cache.Cache cache}s, so it is the Cache manager implementation that
 * determines if this class stores all data in memory or spools to disk or clusters it, etc based on the
 * Caches it creates.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SimpleAccountRealm extends AuthorizingRealm {

    //TODO - complete JavaDoc

    protected Map<String, SimpleRole> roles = null;

    public SimpleAccountRealm() {
        init();
    }

    public SimpleAccountRealm(String name) {
        setName(name);
        init();
    }

    public void afterAuthorizationCacheSet() {
        initRoleCache();
        afterRoleCacheSet();
    }

    public void afterRoleCacheSet() {
    }

    protected void initRoleCache() {
        if (getAuthorizationCache() == null) {
            initAuthorizationCache();
        }

        this.roles = new HashMap<String, SimpleRole>();
        accountAndRoleCachesCreated();
    }

    protected SimpleAccount getUser(String username) {
        return (SimpleAccount) getAuthorizationCache().get(username);
    }

    public boolean accountExists(String username) {
        return getUser(username) != null;
    }

    public void addAccount(String username, String password) {
        addAccount(username, password, (String[]) null);
    }

    public void addAccount(String username, String password, String... roles) {
        Set<String> roleNames = CollectionUtils.asSet(roles);
        SimpleAccount account = new SimpleAuthorizingAccount(username, password, getName(), roleNames, null);
        add(account);
    }

    protected void add(SimpleAccount account) {
        Object key = getAuthorizationCacheKey(account.getPrincipals());
        getAuthorizationCache().put(key, account);
    }

    protected SimpleRole getRole(String rolename) {
        return roles.get(rolename);
    }

    public boolean roleExists(String name) {
        return getRole(name) != null;
    }

    public void addRole(String name) {
        add(new SimpleRole(name));
    }

    protected void add(SimpleRole role) {
        roles.put(role.getName(), role);
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

    protected void accountAndRoleCachesCreated() {
    }

    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        SimpleAccount account = (SimpleAccount) getAuthorizationCache().get(upToken.getUsername());

        if (account != null) {

            if (account.isLocked()) {
                throw new LockedAccountException("Account [" + account + "] is locked.");
            }
            if (account.isCredentialsExpired()) {
                String msg = "The credentials for account [" + account + "] are expired";
                throw new ExpiredCredentialsException(msg);
            }

        }

        return account;
    }

    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        return (Account) getAuthorizationCache().get(getAuthorizationCacheKey(principals));
    }

    protected Object getAuthorizationCacheKey(PrincipalCollection principals) {
        return getAvailablePrincipal(principals); //returns the username, being the only principal from this Realm
    }
}