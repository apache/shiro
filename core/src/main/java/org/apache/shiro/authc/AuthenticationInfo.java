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

import org.apache.shiro.subject.PrincipalCollection;

import java.io.Serializable;

/**
 * <code>AuthenticationInfo</code> represents a Subject's (aka user's) stored account information relevant to the
 * authentication/log-in process only.
 * <p/>
 * It is important to understand the difference between this interface and the
 * {@link AuthenticationToken AuthenticationToken} interface.  <code>AuthenticationInfo</code> implementations
 * represent already-verified and stored account data, whereas an <code>AuthenticationToken</code> represents data
 * submitted for any given login attempt (which may or may not successfully match the verified and stored account
 * <code>AuthenticationInfo</code>).
 * <p/>
 * Because the act of authentication (log-in) is orthogonal to authorization (access control), this interface is
 * intended to represent only the account data needed by Shiro during an authentication attempt.  Shiro also
 * has a parallel {@link org.apache.shiro.authz.AuthorizationInfo AuthorizationInfo} interface for use during the
 * authorization process that references access control data such as roles and permissions.
 * <p/>
 * But because many if not most {@link org.apache.shiro.realm.Realm Realm}s store both sets of data for a Subject, it might be
 * convenient for a <code>Realm</code> implementation to utilize an implementation of the {@link Account Account}
 * interface instead, which is a convenience interface that combines both <code>AuthenticationInfo</code> and
 * <code>AuthorizationInfo</code>.  Whether you choose to implement these two interfaces separately or implement the one
 * <code>Account</code> interface for a given <code>Realm</code> is entirely based on your application's needs or your
 * preferences.
 * <p/>
 * <p><b>Pleae note:</b>  Since Shiro sometimes logs authentication operations, please ensure your AuthenticationInfo's
 * <code>toString()</code> implementation does <em>not</em> print out account credentials (password, etc), as these might be viewable to
 * someone reading your logs.  This is good practice anyway, and account credentials should rarely (if ever) be printed
 * out for any reason.  If you're using Shiro's default implementations of this interface, they only ever print the
 * account {@link #getPrincipals() principals}, so you do not need to do anything additional.</p>
 *
 * @see org.apache.shiro.authz.AuthorizationInfo AuthorizationInfo
 * @see Account
 * @since 0.9
 */
public interface AuthenticationInfo extends Serializable {

    /**
     * Returns all principals associated with the corresponding Subject.  Each principal is an identifying piece of
     * information useful to the application such as a username, or user id, a given name, etc - anything useful
     * to the application to identify the current <code>Subject</code>.
     * <p/>
     * The returned PrincipalCollection should <em>not</em> contain any credentials used to verify principals, such
     * as passwords, private keys, etc.  Those should be instead returned by {@link #getCredentials() getCredentials()}.
     *
     * @return all principals associated with the corresponding Subject.
     */
    PrincipalCollection getPrincipals();

    /**
     * Returns the credentials associated with the corresponding Subject.  A credential verifies one or more of the
     * {@link #getPrincipals() principals} associated with the Subject, such as a password or private key.  Credentials
     * are used by Shiro particularly during the authentication process to ensure that submitted credentials
     * during a login attempt match exactly the credentials here in the <code>AuthenticationInfo</code> instance.
     *
     * @return the credentials associated with the corresponding Subject.
     */
    Object getCredentials();

}
