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
 * A credentials matcher that always returns {@code true} when matching credentials no matter what arguments
 * are passed in. Configuring this matcher on a Realm effectively disables the Realm from performing any credentials
 * comparisons itself.
 * <p/>
 * While this might sound unintuitive ("why would you disable the realm from asserting correct credentials?"), this
 * matcher can be useful when the Realm does not do the credentials matching directly, but instead lets an underlying
 * {@link org.apache.shiro.account.AccountStore AccountStore} do the credentials checking directly.
 * <p/>
 * This is common for example, in LDAP or ActiveDirectory scenarios: if you query LDAP for the account record using
 * the credentials submitted in the {@code AuthenticationToken}, the LDAP server will automatically authenticate the
 * query request before returning the account record.  In this (and similar) authenticated request scenarios, there is
 * no further authentication for the Realm to perform itself, so it can use this {@code AllowAllCredentialsMatcher},
 * effectively trusting the underlying account store to do the authentication work.
 *
 * @since 0.2
 */
public class AllowAllCredentialsMatcher implements CredentialsMatcher {

    /**
     * Returns {@code true} <em>always</em>, ignoring the method arguments.
     *
     * @param token the token submitted for authentication.
     * @param info  the account being verified for access
     * @return {@code true} <em>always</em>, ignoring the method arguments.
     * @deprecated in favor of {@link #credentialsMatch(org.apache.shiro.authc.AuthenticationToken, org.apache.shiro.account.Account)}
     */
    @Deprecated
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        return true;
    }

    /**
     * Returns {@code true} <em>always</em>, ignoring the method arguments.
     *
     * @param token   ignored
     * @param account ignored
     * @return {@code true} <em>always</em>, ignoring the method arguments.
     */
    public boolean credentialsMatch(AuthenticationToken token, Account account) {
        return true;
    }
}
