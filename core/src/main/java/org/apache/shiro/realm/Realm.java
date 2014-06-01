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
import org.apache.shiro.authc.Authenticator;

/**
 * A {@code Realm} access application-specific security entities
 * such as accounts, roles, and permissions to perform authentication and authorization operations.
 * <p/>
 * {@code Realm}s usually have a 1-to-1 correlation with an {@link org.apache.shiro.account.AccountStore account store}
 * such as a NoSQL or relational database, file system, or other similar resource.  However, because most Realm
 * implementations are nearly identical, except for the account query logic, a default realm implementation -
 * {@link AccountStoreRealm} - is provided out of the box, allowing you to configure it with the data API-specific
 * {@link org.apache.shiro.account.AccountStore AccountStore} instance.
 * <p/>
 * Because most account stores usually contain Subject information such as usernames and
 * passwords, a Realm can act as a pluggable authentication module in a
 * <a href="http://en.wikipedia.org/wiki/Pluggable_Authentication_Modules">PAM</a> configuration.  This allows a Realm
 * to perform <i>both</i> authentication and authorization duties for a single account store, which caters to most
 * application needs.  If for some reason you don't want your Realm implementation to participate in authentication,
 * you should override the {@link #supports(org.apache.shiro.authc.AuthenticationToken)} method to always
 * return {@code false}.
 * <p/>
 * Because every application is different, security data such as users and roles can be
 * represented in any number of ways.  Shiro tries to maintain a non-intrusive development philosophy whenever
 * possible - it does not require you to implement or extend any <tt>User</tt>, <tt>Group</tt> or <tt>Role</tt>
 * interfaces or classes.
 * <p/>
 * Instead, Shiro allows applications to implement this interface to access environment-specific account stores
 * and data model objects.  The implementation can then be plugged in to the application's Shiro configuration.
 * This modular technique abstracts away any environment/modeling details and allows Shiro to be deployed in
 * practically any application environment.
 * <p/>
 * Most users will not implement this {@code Realm} interface directly, but will instead use an
 * {@link AccountStoreRealm} instance and configure it with an {@link org.apache.shiro.account.AccountStore AccountStore}.
 * This implies there would be an {@code AccountStoreRealm} instance per {@code AccountStore} that the application needs
 * to access.
 *
 * @see AccountStoreRealm
 * @since 0.1
 */
public interface Realm extends Authenticator {

    /**
     * Returns the (application-unique) name assigned to this {@code Realm}. All realms configured for a single
     * application must have a unique name.
     *
     * @return the (application-unique) name assigned to this {@code Realm}.
     */
    String getName();

    /**
     * Returns {@code true} if this realm can/will authenticate the account corresponding to the specified
     * {@link org.apache.shiro.authc.AuthenticationToken AuthenticationToken} instance, {@code false} otherwise.
     * <p/>
     * If this method returns {@code false}, it will not be called to authenticate the account represented by
     * the token - more specifically, a {@code false} return value means the Realm instance's
     * {@link #authenticateAccount(org.apache.shiro.authc.AuthenticationToken)} method will not be invoked for the
     * specified token.
     *
     * @param token the AuthenticationToken submitted for the authentication attempt
     * @return {@code true} if this realm can/will authenticate the account corresponding to the specified token,
     *         {@code false} otherwise.
     */
    boolean supports(AuthenticationToken token);

    /**
     * Returns an account's authentication-specific information for the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     * <p/>
     * <p>This method effectively represents a login attempt for the corresponding user with the underlying EIS datasource.
     * Most implementations merely just need to lookup and return the account data only (as the method name implies)
     * and let Shiro do the rest, but implementations may of course perform eis specific login operations if so
     * desired.
     *
     * @param token the application-specific representation of an account principal and credentials.
     * @return the authentication information for the account associated with the specified <tt>token</tt>,
     *         or <tt>null</tt> if no account could be found.
     * @throws org.apache.shiro.authc.AuthenticationException
     *          if there is an error obtaining or constructing an AuthenticationInfo object based on the
     *          specified <tt>token</tt> or implementation-specifc login behavior fails.
     * @deprecated as of Shiro 2.0, Realm extends Authenticator.  Implement
     *             {@link #authenticateAccount(org.apache.shiro.authc.AuthenticationToken)} and have this method
     *             delegate to it.  This method will be removed before the 2.0 final release.
     */
    @Deprecated
    AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

}
