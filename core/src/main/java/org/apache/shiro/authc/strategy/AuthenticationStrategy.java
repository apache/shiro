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
package org.apache.shiro.authc.strategy;

import org.apache.shiro.account.Account;
import org.apache.shiro.authc.AuthenticationException;

/**
 * A{@code AuthenticationStrategy} implementation attempts to authenticate an account by consulting one or more
 * {@link org.apache.shiro.realm.Realm Realm}s. This interface enables the
 * <a href="http://en.wikipedia.org/wiki/Strategy_pattern">Strategy Design Pattern</a> for authentication, allowing a
 * Shiro user to customize an {@link org.apache.shiro.authc.Authenticator Authenticator}'s authentication processing
 * logic.
 * <p/>
 * Most Shiro users will find one of the existing Strategy implementations suitable for most needs, but if those are
 * not sufficient, custom logic can be performed by implementing this interface.
 *
 * @see FirstRealmSuccessfulStrategy
 * @see AllRealmsSuccessfulStrategy
 * @see FirstRealmSuccessfulStrategy
 * @see org.apache.shiro.authc.DefaultAuthenticator DefaultAuthenticator
 * @since 2.0
 */
public interface AuthenticationStrategy {

    /**
     * Authenticates a submitted authentication token by consulting one or more provided
     * {@link org.apache.shiro.authc.strategy.AuthenticationAttempt#getRealms() realms} and returns an
     * {@link Account} instance reflecting the authenticated identity, or {@code null} if no account could be
     * returned.
     *
     * @param attempt the attempt instance encompassing the submitted {@link org.apache.shiro.authc.AuthenticationToken AuthenticationToken}
     *                and {@link org.apache.shiro.realm.Realm Realm}s to consult.
     * @return an {@link Account} instance reflecting the authenticated identity, or {@code null} if no account could be returned.
     * @throws AuthenticationException if there is an error during authentication.
     */
    Account execute(AuthenticationAttempt attempt) throws AuthenticationException;

}
