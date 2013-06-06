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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExpiredCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleRole;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.CollectionUtils;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * A simple implementation of the {@link Realm Realm} interface that
 * uses a set of configured user accounts and roles to support authentication and authorization.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and associated with users.
 * <p/>
 * User accounts and roles are stored in two {@code Map}s in memory, so it is expected that the total number of either
 * is not sufficiently large.
 *
 * @since 0.1
 */
public class SimpleAccountRealm extends AuthorizingRealm {

    //TODO - complete JavaDoc
    protected final Map<String, SimpleAccount> users; //username-to-SimpleAccount
    protected final Map<String, SimpleRole> roles; //roleName-to-SimpleRole
    protected final ReadWriteLock USERS_LOCK;
    protected final ReadWriteLock ROLES_LOCK;

    public SimpleAccountRealm() {
        this.users = new LinkedHashMap<String, SimpleAccount>();
        this.roles = new LinkedHashMap<String, SimpleRole>();
        USERS_LOCK = new ReentrantReadWriteLock();
        ROLES_LOCK = new ReentrantReadWriteLock();
        //SimpleAccountRealms are memory-only realms - no need for an additional cache mechanism since we're
        //already as memory-efficient as we can be:
        setCachingEnabled(false);
    }

    public SimpleAccountRealm(String name) {
        this();
        setName(name);
    }

    protected SimpleAccount getUser(String username) {
        USERS_LOCK.readLock().lock();
        try {
            return this.users.get(username);
        } finally {
            USERS_LOCK.readLock().unlock();
        }
    }

    public boolean accountExists(String username) {
        return getUser(username) != null;
    }

    public void addAccount(String username, String password) {
        addAccount(username, password, (String[]) null);
    }

    public void addAccount(String username, String password, String... roles) {
        Set<String> roleNames = CollectionUtils.asSet(roles);
        SimpleAccount account = new SimpleAccount(username, password, getName(), roleNames, null);
        add(account);
    }

    protected String getUsername(SimpleAccount account) {
        return getUsername(account.getPrincipals());
    }

    protected String getUsername(PrincipalCollection principals) {
        return getAvailablePrincipal(principals).toString();
    }

    protected void add(SimpleAccount account) {
        String username = getUsername(account);
        USERS_LOCK.writeLock().lock();
        try {
            this.users.put(username, account);
        } finally {
            USERS_LOCK.writeLock().unlock();
        }
    }

    protected SimpleRole getRole(String rolename) {
        ROLES_LOCK.readLock().lock();
        try {
            return roles.get(rolename);
        } finally {
            ROLES_LOCK.readLock().unlock();
        }
    }

    public boolean roleExists(String name) {
        return getRole(name) != null;
    }

    public void addRole(String name) {
        add(new SimpleRole(name));
    }

    protected void add(SimpleRole role) {
        ROLES_LOCK.writeLock().lock();
        try {
            roles.put(role.getName(), role);
        } finally {
            ROLES_LOCK.writeLock().unlock();
        }
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

    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        SimpleAccount account = getUser(upToken.getUsername());

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
        String username = getUsername(principals);
        USERS_LOCK.readLock().lock();
        try {
            return this.users.get(username);
        } finally {
            USERS_LOCK.readLock().unlock();
        }
    }
}