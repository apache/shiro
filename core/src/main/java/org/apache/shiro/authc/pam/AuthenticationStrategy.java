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
package org.apache.shiro.authc.pam;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.Realm;

import java.util.Collection;


/**
 * A {@code AuthenticationStrategy} implementation assists the {@link ModularRealmAuthenticator} during the
 * log-in process in a pluggable realm (PAM) environment.
 *
 * <p>The {@code ModularRealmAuthenticator} will consult implementations of this interface on what to do during each
 * interaction with the configured Realms.  This allows a pluggable strategy of whether or not an authentication
 * attempt must be successful for all realms, only 1 or more realms, no realms, etc.
 *
 * @see AllSuccessfulStrategy
 * @see AtLeastOneSuccessfulStrategy
 * @see FirstSuccessfulStrategy
 * @since 0.2
 */
public interface AuthenticationStrategy {

    /**
     * Method invoked by the ModularAuthenticator signifying that the authentication process is about to begin for the
     * specified {@code token} - called before any {@code Realm} is actually invoked.
     *
     * <p>The {@code AuthenticationInfo} object returned from this method is essentially an empty place holder for
     * aggregating account data across multiple realms.  It should be populated by the strategy implementation over the
     * course of authentication attempts across the multiple realms.  It will be passed into the
     * {@link #beforeAttempt} calls, allowing inspection of the aggregated account data up to that point in the
     * multi-realm authentication, allowing any logic to be executed accordingly.
     *
     * @param realms the Realms that will be consulted during the authentication process for the specified token.
     * @param token  the Principal/Credential representation to be used during authentication for a corresponding subject.
     * @return an empty AuthenticationInfo object that will populated with data from multiple realms.
     * @throws AuthenticationException if the strategy implementation does not wish the Authentication attempt to execute.
     */
    AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> realms, AuthenticationToken token) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just prior to the realm being consulted for account data,
     * allowing pre-authentication-attempt logic for that realm only.
     *
     * <p>This method returns an {@code AuthenticationInfo} object that will be used for further interaction with realms.  Most
     * implementations will merely return the {@code aggregate} method argument if they don't have a need to
     * manipulate it.
     *
     * @param realm     the realm that will be consulted for {@code AuthenticationInfo} for the specified {@code token}.
     * @param token     the {@code AuthenticationToken} submitted for the subject attempting system log-in.
     * @param aggregate the aggregated AuthenticationInfo object being used across the multi-realm authentication attempt
     * @return the AuthenticationInfo object that will be presented to further realms in the authentication process - returning
     *         the {@code aggregate} method argument is the normal case if no special action needs to be taken.
     * @throws org.apache.shiro.authc.AuthenticationException
     *          an exception thrown by the Strategy implementation if it wishes the login
     *          process for the associated subject (user) to stop immediately.
     */
    AuthenticationInfo beforeAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just after the given realm has been consulted for authentication,
     * allowing post-authentication-attempt logic for that realm only.
     *
     * <p>This method returns an {@code AuthenticationInfo} object that will be used for further interaction with realms.  Most
     * implementations will merge the {@code singleRealmInfo} into the {@code aggregateInfo} and
     * just return the {@code aggregateInfo} for continued use throughout the authentication process.</p>
     *
     * @param realm           the realm that was just consulted for {@code AuthenticationInfo} for the given {@code token}.
     * @param token           the {@code AuthenticationToken} submitted for the subject attempting system log-in.
     * @param singleRealmInfo the info returned from a single realm.
     * @param aggregateInfo   the aggregate info representing all realms in a multi-realm environment.
     * @param t               the Throwable thrown by the Realm during the attempt, or {@code null} if the method returned normally.
     * @return the AuthenticationInfo object that will be presented to further realms in the authentication process - returning
     *         the {@code aggregateAccount} method argument is the normal case if no special action needs to be taken.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login process
     *                                 for the associated subject (user) to stop immediately.
     */
    AuthenticationInfo afterAttempt(Realm realm, AuthenticationToken token, AuthenticationInfo singleRealmInfo, AuthenticationInfo aggregateInfo, Throwable t)
            throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator signifying that all of its configured Realms have been consulted
     * for account data, allowing post-processing after all realms have completed.
     *
     * <p>Returns the final AuthenticationInfo object that will be returned from the Authenticator to the authenticate() caller.
     * This is most likely the aggregate AuthenticationInfo object that has been populated by many realms, but the actual return value is
     * always up to the implementation.
     *
     * @param token     the {@code AuthenticationToken} submitted for the subject attempting system log-in.
     * @param aggregate the aggregate {@code AuthenticationInfo} instance populated by all realms during the log-in attempt.
     * @return the final {@code AuthenticationInfo} object to return to the Authenticator.authenticate() caller.
     * @throws AuthenticationException if the Strategy implementation wishes to fail the authentication attempt.
     */
    AuthenticationInfo afterAllAttempts(AuthenticationToken token, AuthenticationInfo aggregate) throws AuthenticationException;
}
