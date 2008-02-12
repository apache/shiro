/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.authc;

import java.util.List;

/**
 * <p>An <tt>Account</tt> implementation represents system-specific account/user information
 * in a framework-independent manner.  Instead of forcing a JSecurity user to
 * implement <tt>User</tt> or <tt>Role</tt> interfaces and being invasive on an application's
 * data model, the application must instead only implement this interface to represent such
 * data.  This enables a cleaner pluggable implementation and abstracts an application's
 * core classes away from JSecurity.</p>
 *
 * <p>This interface is used by all realms, since it is referenced from the {@link org.jsecurity.realm.Realm} interface.
 * Most realms will probably use the {@link org.jsecurity.authc.support.SimpleAccount} implementation, but are of course
 * free to create their own their own.</p>
 *
 * @see org.jsecurity.authc.support.SimpleAccount
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 1.0
 */
public interface Account {

    /**
     * Returns the account's primary principal, such as a user id or username.
     *
     * <p>In a multi-realm configuration, if this instance is an
     * {@link org.jsecurity.authc.support.AggregateAccount AggregateAccount}, the object returned from this method
     * might be an implementation-specific object representing multiple principals.  This might be an instance of
     * java.util.Collection, but it does not have to be - it is up to the Authenticator and Realm implementations as to
     * what is returned.
     *
     * @return the account's primary principal, such as a user id or username, or in a multi-realm configuration, maybe
     * more than one principal encapsulated by an implementation-specific instance.
     */
    Object getPrincipal();

    /**
     * Returns the principals that identify the account, such as a user's primary key
     * id or username.  Although not a requirement,
     * the list returned by the implementation should contain at least 1 principal.  The first
     * pricipal in the list is usually (but still not a requirement) the account's primary
     * principal (e.g. user id).
     *
     * @return the account's identifying principals.
     */
    List<Object> getPrincipals();

    /**
     * The account's credentials as stored in the system associated with the
     * {@link #getPrincipals() account identifier}, such as a password char array or
     * public key.
     *
     * <p>It could be encrypted in which case an
     * {@link org.jsecurity.realm.Realm Realm}
     * must be aware of the fact (e.g. via configuration) in order to interpret and compare
     * the credentials value.
     *
     * @return the account's credential verifying the {@link #getPrincipals() identifier}
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
     * Determines if the user's credentials (e.g. password) has expired and must be
     * changed before login is allowed.
     *
     * @return true if the user's credentials are expired and the user should
     *         be denied authentication, false otherwise.
     */
    boolean isCredentialsExpired();


    /**
     * Determines if the user is allowed to concurrently login from two
     * unique sessions.  For example, if Joe needs the ability to leave
     * an account logged in at home and still log in from work, then
     * concurrent logins should be enabled.  This feature is mainly intended
     * to prevent account sharing where a user distributes his password to
     * others who log in concurrently.
     *
     * @return true if the user should be allowed to login concurrently,
     *         false otherwise.
     */
    boolean isConcurrentLoginsAllowed();

}