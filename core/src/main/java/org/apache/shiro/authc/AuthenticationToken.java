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

import java.io.Serializable;

/**
 * <p>An <tt>AuthenticationToken</tt> is a consolidation of an account's principals and supporting
 * credentials submitted by a user during an authentication attempt.
 * <p/>
 * <p>The token is submitted to an {@link Authenticator Authenticator} via the
 * {@link Authenticator#authenticate(AuthenticationToken) authenticate(token)} method.  The
 * Authenticator then executes the authentication/log-in process.
 * <p/>
 * <p>Common implementations of an <tt>AuthenticationToken</tt> would have username/password
 * pairs, X.509 Certificate, PGP key, or anything else you can think of.  The token can be
 * anything needed by an {@link Authenticator} to authenticate properly.
 * <p/>
 * <p>Because applications represent user data and credentials in different ways, implementations
 * of this interface are application-specific.  You are free to acquire a user's principals and
 * credentials however you wish (e.g. web form, Swing form, fingerprint identification, etc) and
 * then submit them to the Shiro framework in the form of an implementation of this
 * interface.
 * <p/>
 * <p>If your application's authentication process is  username/password based
 * (like most), instead of implementing this interface yourself, take a look at the
 * {@link UsernamePasswordToken UsernamePasswordToken} class, as it is probably sufficient for your needs.
 * <p/>
 * <p>RememberMe services are enabled for a token if they implement a sub-interface of this one, called
 * {@link RememberMeAuthenticationToken RememberMeAuthenticationToken}.  Implement that interfac if you need
 * RememberMe services (the <tt>UsernamePasswordToken</tt> already implements this interface).
 * <p/>
 * <p>If you are familiar with JAAS, an <tt>AuthenticationToken</tt> replaces the concept of a
 * {@link javax.security.auth.callback.Callback}, and  defines meaningful behavior
 * (<tt>Callback</tt> is just a marker interface, and of little use).  We
 * also think the name <em>AuthenticationToken</em> more accurately reflects its true purpose
 * in a login framework, whereas <em>Callback</em> is less obvious.
 *
 * @see RememberMeAuthenticationToken
 * @see HostAuthenticationToken
 * @see UsernamePasswordToken
 * @since 0.1
 */
public interface AuthenticationToken extends Serializable {

    /**
     * Returns the account identity submitted during the authentication process.
     * <p/>
     * <p>Most application authentications are username/password based and have this
     * object represent a username.  If this is the case for your application,
     * take a look at the {@link UsernamePasswordToken UsernamePasswordToken}, as it is probably
     * sufficient for your use.
     * <p/>
     * <p>Ultimately, the object returned is application specific and can represent
     * any account identity (user id, X.509 certificate, etc).
     *
     * @return the account identity submitted during the authentication process.
     * @see UsernamePasswordToken
     */
    Object getPrincipal();

    /**
     * Returns the credentials submitted by the user during the authentication process that verifies
     * the submitted {@link #getPrincipal() account identity}.
     * <p/>
     * <p>Most application authentications are username/password based and have this object
     * represent a submitted password.  If this is the case for your application,
     * take a look at the {@link UsernamePasswordToken UsernamePasswordToken}, as it is probably
     * sufficient for your use.
     * <p/>
     * <p>Ultimately, the credentials Object returned is application specific and can represent
     * any credential mechanism.
     *
     * @return the credential submitted by the user during the authentication process.
     */
    Object getCredentials();

}
