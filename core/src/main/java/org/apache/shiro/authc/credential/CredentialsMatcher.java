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
package org.apache.shiro.authc.credential;

import org.apache.shiro.account.Account;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;


/**
 * Interface implemented by classes that can determine if an AuthenticationToken's provided
 * credentials matches a corresponding account's credentials stored in the system.
 * <p/>
 * <p>Simple direct comparisons are handled well by the
 * {@link SimpleCredentialsMatcher SimpleCredentialsMatcher}.  If you
 * hash user's credentials (passwords) before storing them in a realm (a common practice), look at the
 * {@link PasswordMatcher PasswordMatcher}.
 *
 * @see PasswordMatcher
 * @see SimpleCredentialsMatcher
 * @see AllowAllCredentialsMatcher
 * @since 0.1
 */
public interface CredentialsMatcher {

    /**
     * Returns {@code true} if the provided token credentials match the stored account credentials,
     * {@code false} otherwise.
     *
     * @param token the {@code AuthenticationToken} submitted during the authentication attempt
     * @param info  the {@code AuthenticationInfo} stored in the system.
     * @return {@code true} if the provided token credentials match the stored account credentials,
     *         {@code false} otherwise.
     * @deprecated since 2.0 in favor of {@link #credentialsMatch(org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.account.Account)}
     */
    @Deprecated
    boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info);

    /**
     * Returns {@code true} if the provided token credentials match the stored account credentials,
     * {@code false} otherwise.
     *
     * @param token   the {@code AuthenticationToken} submitted during the authentication attempt
     * @param account the stored {@code Account} found based on the submitted token
     *                {@link org.apache.shiro.authc.AuthenticationToken#getPrincipal() principal}.
     * @return {@code true} if the provided token credentials match the stored account credentials,
     *         {@code false} otherwise.
     */
    boolean credentialsMatch(AuthenticationToken token, Account account);

}