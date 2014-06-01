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
package org.apache.shiro.account;

import java.io.Serializable;
import java.util.Map;

/**
 * An {@code Account} is a unique identity within an {@link AccountStore AccountStore} that
 * has a set of attributes.  An account may represent a human being, but this is not required - an account could
 * represent a host, a server, a daemon - basically anything with an identity that might need to be authenticated or
 * authorized to perform behavior.
 * <h3>Implementation Warning</h3>
 * Since Shiro sometimes logs account operations, please ensure your Account's <code>toString()</code>
 * implementation does <em>not</em> print out account credentials (password, etc), as these might be viewable to
 * someone reading your logs.  This is good practice anyway, and account principals should rarely (if ever) be printed
 * out for any reason.
 * <p/>
 * Shiro's default implementations of this interface only ever print {@link #getAttributes() attributes}.
 *
 * @since 2.0
 */
public interface Account extends Serializable {

    /**
     * Returns an identifier unique compared to any other Account found in the same account store.  For example,
     * this can be a store-wide unique username or email address, database primary key, UUID, GUID, etc.
     * <p/>
     * After an account is authenticated, Shiro will use this id for all future access to the account: for caching
     * the account (if caching is enabled), for future lookups from the account store, and any lookups for authorization.
     *
     * @return an identifier unique compared to any other Account found in the same account store.
     */
    AccountId getId();

    /**
     * Returns the stored credentials associated with the corresponding Account.  Credentials, such as a password or
     * private key, verifies one or more submitted identities during authentication.
     * <p/>
     * Shiro references credentials during the authentication process to ensure that submitted credentials
     * during a login attempt match exactly the Account's stored credentials returned via this method.
     *
     * @return the credentials associated with the corresponding Subject.
     */
    Object getCredentials();

    /**
     * Returns an <b><em>immutable</em></b> view of the Account's attributes accessible to the application.
     * Once the account is obtained, an application developer can access them as desired, for example:
     * <pre>
     * String username = (String)account.getAttributes().get("username");
     * System.out.println("Welcome, " + username + "!");
     * </pre>
     *
     * @return the Account's attributes accessible to the application.
     */
    Map<String, Object> getAttributes();

}
