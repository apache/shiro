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
package org.apache.shiro.authc;

/**
 * An Authenticator is responsible for authenticating accounts in an application.  It
 * is one of the primary entry points into the Shiro API.
 * <p/>
 * Although not a requirement, there is usually a single 'master' Authenticator configured for
 * an application.  Enabling Pluggable Authentication Module (PAM) behavior
 * (Two Phase Commit, etc.) is usually achieved by the single {@code Authenticator} coordinating
 * and interacting with an application-configured set of {@link org.apache.shiro.realm.Realm Realm}s.
 * <p/>
 * Note that most Shiro users will not interact with an {@code Authenticator} instance directly.
 * Shiro's default architecture is based on an overall {@code SecurityManager} which typically
 * wraps an {@code Authenticator} instance.
 *
 * @see org.apache.shiro.mgt.SecurityManager
 * @see AbstractAuthenticator AbstractAuthenticator
 * @see org.apache.shiro.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator
 * @since 0.1
 */
public interface Authenticator {

    /**
     * Authenticates a user based on the submitted {@code AuthenticationToken}.
     * <p/>
     * If the authentication is successful, an {@link AuthenticationInfo} instance is returned that represents the
     * user's account data relevant to Shiro.  This returned object is generally used in turn to construct a
     * {@code Subject} representing a more complete security-specific 'view' of an account that also allows access to
     * a {@code Session}.
     *
     * @param authenticationToken any representation of a user's principals and credentials submitted during an
     *                            authentication attempt.
     * @return the AuthenticationInfo representing the authenticating user's account data.
     * @throws AuthenticationException if there is any problem during the authentication process.
     *                                 See the specific exceptions listed below to as examples of what could happen
     *                                 in order to accurately handle these problems and to notify the user in an
     *                                 appropriate manner why the authentication attempt failed.  Realize an
     *                                 implementation of this interface may or may not throw those listed or may
     *                                 throw other AuthenticationExceptions, but the list shows the most common ones.
     * @see ExpiredCredentialsException
     * @see IncorrectCredentialsException
     * @see ExcessiveAttemptsException
     * @see LockedAccountException
     * @see ConcurrentAccessException
     * @see UnknownAccountException
     */
    public AuthenticationInfo authenticate(AuthenticationToken authenticationToken)
            throws AuthenticationException;
}
