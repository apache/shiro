/*
 * Copyright 2005-2008 Les Hazlewood, Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.authc;

import org.jsecurity.subject.PrincipalCollection;

/**
 * <p>An <tt>Account</tt> represents system-specific account/user information
 * in an application-independent manner.  Instead of forcing a JSecurity user to
 * implement <tt>User</tt> or <tt>Role</tt> interfaces and being invasive on an application's
 * data model, the application instead returns instances of this interface to represent such data.  This enables a
 * cleaner pluggable implementation and abstracts an application's core classes away from JSecurity.</p>
 *
 * <p>In fact, JSecurity's default implementations of this interface are usually good for the majority of applications
 * and no additional implementation is required.
 *
 * <p>Please note:  Since JSecurity sometimes logs account operations, please ensure your Account's <code>toString()</code>
 * implementation does <em>not</em> print out account credentials (password, etc), as these might be viewable to
 * someone reading your logs.  This is good practice anyway, and account principals should rarely (if ever) be printed
 * out for any reason.  If you're using JSecurity's default implementations of this interface, they only ever print the
 * account {@link #getPrincipals() principals}, so you do not need to do anything additional.</p>
 *
 * @see SimpleAccount
 * @see org.jsecurity.authz.SimpleAuthorizingAccount
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.9
 */
public interface Account {

    /**
     * Returns the account's identifying principals, such as a user id or username.
     *
     * <p>In most simple and single-realm configurations, the returned collection contains only a single principal,
     * such as a user id or username.</p>
     *
     * //TODO - update JavaDoc for multi-realm scenario.
     *
     *
     * @return the account's primary principal, such as a user id or username, or in a multi-realm configuration, maybe
     * more than one principal encapsulated by an implementation-specific instance.
     */
    PrincipalCollection getPrincipals();

    /**
     * The account's credentials as stored in the system associated with the
     * {@link #getPrincipals() account identifier}, such as a password or private key.
     *
     * <p>It could be encrypted in which case an
     * {@link org.jsecurity.realm.Realm Realm}
     * must be aware of the fact (e.g. via configuration) in order to interpret and compare
     * the credentials value.
     *
     * @return the account's credentials verifying the {@link #getPrincipals() identifiers}
     */
    Object getCredentials();

    /**
     * Determines if the account is locked, meaning that the user is
     * not allowed to log in due to a manual or automatic lockout.
     *
     * @return true if the account is locked and the user should be
     *         denied authentication, false otherwise.
     */
    boolean isLocked();


    /**
     * Determines if the user's credentials (e.g. password) have expired and must be
     * changed before login is allowed.
     *
     * @return true if the user's credentials are expired and the user should
     *         be denied authentication, false otherwise.
     */
    boolean isCredentialsExpired();

}