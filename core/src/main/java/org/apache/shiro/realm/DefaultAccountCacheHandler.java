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
import org.apache.shiro.account.AccountId;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.cache.Cache;

/**
 * @since 2.0
 */
public class DefaultAccountCacheHandler extends AbstractCacheHandler implements AccountCacheHandler {

    private AccountCacheKeyResolver accountCacheKeyResolver;
    private AccountCacheResolver accountCacheResolver;

    public DefaultAccountCacheHandler() {
    }

    public Account getCachedAccount(AuthenticationToken token) {
        Cache<Object,Account> cache = accountCacheResolver.getAccountCache(token);
        Object key = accountCacheKeyResolver.getAccountCacheKey(token);
        return cache.get(key);
    }

    public void cacheAccount(AuthenticationToken token, Account account) {
        Cache<Object,Account> cache = accountCacheResolver.getAccountCache(token, account);
        Object key = accountCacheKeyResolver.getAccountCacheKey(token, account);
        cache.put(key, account);
    }

    public void clearCachedAccount(AccountId id) {
        Cache<Object,Account> cache = accountCacheResolver.getAccountCache(id);
        Object key = accountCacheKeyResolver.getAccountCacheKey(id);
        cache.remove(key);
    }

    public AccountCacheKeyResolver getAccountCacheKeyResolver() {
        return accountCacheKeyResolver;
    }

    public void setAccountCacheKeyResolver(AccountCacheKeyResolver accountCacheKeyResolver) {
        this.accountCacheKeyResolver = accountCacheKeyResolver;
    }

    public AccountCacheResolver getAccountCacheResolver() {
        return accountCacheResolver;
    }

    public void setAccountCacheResolver(AccountCacheResolver accountCacheResolver) {
        this.accountCacheResolver = accountCacheResolver;
    }
}
