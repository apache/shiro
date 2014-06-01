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

import org.apache.shiro.account.Account;
import org.apache.shiro.account.AccountStore;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authc.credential.PasswordMatcher;
import org.apache.shiro.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Performs authentication and authorization for accounts in a <em>single</em> account data store.  It is expected
 * that you configure one {@code AccountStoreRealm} for each data store that contains accounts accessible to your
 * application.
 *
 * @since 2.0
 */
public class AccountStoreRealm implements Realm {

    private static final Logger log = LoggerFactory.getLogger(AccountStoreRealm.class);

    private String name;

    private AccountStore accountStore;

    //Authentication:
    private CredentialsMatcher credentialsMatcher;
    private AccountCacheHandler accountCacheHandler;

    //Authorization:
    private AuthorizationCacheHandler authorizationCacheHandler;
    private AccountRoleResolver accountRoleResolver;
    private AccountRolePermissionResolver accountRolePermissionResolver;
    private AccountPermissionResolver accountPermissionResolver;

    public AccountStoreRealm() {
        this.credentialsMatcher = new PasswordMatcher(); //80/20 rule: most Shiro deployments use passwords
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public AccountStore getAccountStore() {
        return accountStore;
    }

    public void setAccountStore(AccountStore accountStore) {
        Assert.notNull(accountStore);
        this.accountStore = accountStore;
    }

    public CredentialsMatcher getCredentialsMatcher() {
        return credentialsMatcher;
    }

    public void setCredentialsMatcher(CredentialsMatcher credentialsMatcher) {
        Assert.notNull(credentialsMatcher);
        this.credentialsMatcher = credentialsMatcher;
    }

    public AccountCacheHandler getAccountCacheHandler() {
        return accountCacheHandler;
    }

    public void setAccountCacheHandler(AccountCacheHandler accountCacheHandler) {
        Assert.notNull(accountCacheHandler);
        this.accountCacheHandler = accountCacheHandler;
    }

    public AuthorizationCacheHandler getAuthorizationCacheHandler() {
        return authorizationCacheHandler;
    }

    public void setAuthorizationCacheHandler(AuthorizationCacheHandler authorizationCacheHandler) {
        Assert.notNull(authorizationCacheHandler);
        this.authorizationCacheHandler = authorizationCacheHandler;
    }

    public boolean supports(AuthenticationToken token) {
        return UsernamePasswordToken.class.isInstance(token);
    }

    @Deprecated
    public final AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        throw new UnsupportedOperationException("The " + getClass().getName() + " implementation does not support " +
                "legacy (pre 2.0) authentication behavior.  Do not configure this Realm unless you are using " +
                "a DefaultAuthenticator implementation.");
    }

    @Deprecated
    public final AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        throw new UnsupportedOperationException("The " + getClass().getName() + " implementation does not support " +
                "legacy (pre 2.0) authentication behavior.  Do not configure this Realm unless you are using " +
                "a DefaultAuthenticator implementation.");
    }

    public Account authenticateAccount(AuthenticationToken token) throws AuthenticationException {
        Account account = accountCacheHandler.getCachedAccount(token);
        if (account == null) {
            //otherwise not cached, perform the lookup:
            account = accountStore.getAccount(token);
            if (token != null && account != null) {
                log.debug("Acquired Account [{}] from account store", account);
                accountCacheHandler.cacheAccount(token, account);
            }
        } else {
            log.debug("Using cached account [{}] for credentials matching.", account);
        }

        if (account == null) {
            log.debug("No account found for submitted AuthenticationToken [{}].  Returning null.", token);
            return null;
        }

        assertCredentialsMatch(token, account);

        return account;
    }

    protected void assertCredentialsMatch(AuthenticationToken token, Account account) {
        CredentialsMatcher cm = getCredentialsMatcher();
        if (!cm.credentialsMatch(token, account)) {
            //not successful - throw an exception to indicate this:
            String msg = "Submitted credentials for token [" + token + "] did not match the stored credentials.";
            throw new IncorrectCredentialsException(msg);
        }
    }
}
