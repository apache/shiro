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
package org.jsecurity.realm;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.subject.PrincipalCollection;

/**
 * A <tt>Realm</tt> is a security component that can access application-specific security entities
 * such as users, roles, and permissions to determine authentication and authorization operations.
 *
 * <p><tt>Realm</tt>s usually have a 1-to-1 correspondance with a datasource such as a relational database,
 * file sysetem, or other similar resource.  As such, implementations of this interface use datasource-specific APIs to
 * determine authorization data (roles, permissions, etc), such as JDBC, File IO, Hibernate or JPA, or any other
 * Data Access API.  They are essentially security-specific
 * <a href="http://en.wikipedia.org/wiki/Data_Access_Object" target="_blank">DAO</a>s.
 *
 * <p>Because most of these datasources usually contain Subject (a.k.a. User) information such as usernames and
 * passwords, a Realm can act as a pluggable authentication module in a PAM configuration.  This allows a Realm to
 * perform <i>both</i> authentication and authorization duties for a single datasource, which caters to the large
 * majority of applications.  If for some reason you don't want your Realm implementation to perform authentication
 * duties, you should override the {@link #supports(org.jsecurity.authc.AuthenticationToken)} method to always
 * return <tt>false</tt>.
 *
 * <p>Because every application is different, security data such as users and roles can be
 * represented in any number of ways.  JSecurity tries to maintain a non-intrusive development philosophy whenever
 * possible - it does not require you to implement or extend any <tt>User</tt>, <tt>Group</tt> or <tt>Role</tt>
 * interfaces or classes.
 *
 * <p>Instead, JSecurity allows applications to implement this interface to access environment-specific datasources
 * and data model objects.  The implementation can then be plugged in to the application's JSecurity configuration.
 * This modular technique abstracts away any environment/modeling details and allows JSecurity to be deployed in
 * practically any application environment.
 *
 * <p>Most users will not implement the <tt>Realm</tt> interface directly, but will extend one of the subclasses,
 * {@link AuthenticatingRealm AuthenticatingRealm} or {@link AuthorizingRealm}, greatly reducing the effort requird
 * to implement a <tt>Realm</tt> from scratch.</p>
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @see CachingRealm CachingRealm
 * @see AuthenticatingRealm AuthenticatingRealm
 * @see AuthorizingRealm AuthorizingRealm
 * @see org.jsecurity.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator
 * @since 0.1
 */
public interface Realm extends Authorizer {

    /**
     * Returns the (application-unique) name assigned to this <code>Realm</code>. All realms configured for a single
     * application must have a unique name.
     *
     * @return the (application-unique) name assigned to this <code>Realm</code>.
     */
    String getName();

    /**
     * Returns <tt>true</tt> if this realm wishes to authenticate the Subject represented by the given
     * {@link org.jsecurity.authc.AuthenticationToken AuthenticationToken} instance, <tt>false</tt> otherwise.
     *
     * <p>If this method returns <tt>false</tt>, it will not be called to authenticate the Subject represented by
     * the token - more specifically, a <tt>false</tt> return value means this Realm instance's
     * {@link #getAuthenticationInfo} method will not be invoked for that token.
     *
     * @param token the AuthenticationToken submitted for the authentication attempt
     * @return <tt>true</tt> if this realm can/will authenticate Subjects represented by specified token,
     *         <tt>false</tt> otherwise.
     */
    boolean supports(AuthenticationToken token);

    /**
     * Returns an account's authentication-specific information for the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     *
     * <p>This method effectively represents a login attempt for the corresponding user with the underlying EIS datasource.
     * Most implementations merely just need to lookup and return the account data only (as the method name implies)
     * and let JSecurity do the rest, but implementations may of course perform eis specific login operations if so
     * desired.
     *
     * @param token the application-specific representation of an account principal and credentials.
     * @return the authentication information for the account associated with the specified <tt>token</tt>,
     *         or <tt>null</tt> if no account could be found.
     * @throws org.jsecurity.authc.AuthenticationException
     *          if there is an error obtaining or constructing an AuthenticationInfo object based on the
     *          specified <tt>token</tt> or implementation-specifc login behavior fails.
     */
    AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) throws AuthenticationException;

    /**
     * Returns an account's authorization-specific information for the specified <code>principals</code>,
     * or <tt>null</tt> if no account could be found.
     *
     * <p>This resulting <code>AuthorizationInfo</code> data is used by JSecurity to perform access control checks for
     * the corresponding <code>Subject</code>.
     *
     * <p>Invocations of this method should be thought of as completely orthogonal to acquiring
     * {@link #getAuthenticationInfo(org.jsecurity.authc.AuthenticationToken) authenticationInfo}, since either could
     * occur in any order.
     *
     * <p>For example, in &quot;Remember Me&quot; scenarios, the user identity is remembered (and
     * assumed) for their current session and an authentication attempt during that session might never occur.
     * But because their identity would be remembered, that is sufficient enough information to call this method to
     * execute any necessary authorization checks.  For this reason, authentication and authorization should be
     * loosely coupled and not depend on each other.
     *
     * @param principals the corresponding Subject's identifying principals with which to look up the Subject's
     *                   <code>AuthorizationInfo</code>.
     * @return the authorization information for the account associated with the specified <code>principals</code>,
     *         or <tt>null</tt> if no account could be found.
     */
    AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals);

}