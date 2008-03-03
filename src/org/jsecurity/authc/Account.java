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

/**
 * <p>An <tt>Account</tt> represents system-specific account/user information
 * in an application-independent manner.  Instead of forcing a JSecurity user to
 * implement <tt>User</tt> or <tt>Role</tt> interfaces and being invasive on an application's
 * data model, the application must instead only implement this interface to represent such
 * data.  This enables a cleaner pluggable implementation and abstracts an application's
 * core classes away from JSecurity.</p>
 *
 * <p>Please note:  Since JSecurity sometimes logs account operations, please ensure your Account's <code>toString()</code>
 * implementation does <em>not</em> print out account credentials (password, etc), as these might be viewable to
 * someone reading your logs.  This is good practice anyway, and account principals should rarely (if ever) be printed
 * out for any reason.  If you're using JSecurity's default implementations of this interface, they only ever print the
 * account {@link #getPrincipal() principal}, so you do not need to do anything additional.</p>
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
     * Returns the account's identifying principal, such as a user id or username.
     *
     * <p>In a multi-realm configuration, if this instance is an
     * {@link org.jsecurity.authc.pam.AggregateAccount AggregateAccount}, the object returned from this method
     * might be an implementation-specific object representing multiple principals.  This might be an instance of
     * java.util.Collection, but it does not have to be - it is up to the Authenticator and Realm implementations as to
     * what is returned.
     *
     * @return the account's primary principal, such as a user id or username, or in a multi-realm configuration, maybe
     * more than one principal encapsulated by an implementation-specific instance.
     */
    Object getPrincipal();

    /**
     * The account's credentials as stored in the system associated with the
     * {@link #getPrincipal() account identifier}, such as a password or private key.
     *
     * <p>It could be encrypted in which case an
     * {@link org.jsecurity.realm.Realm Realm}
     * must be aware of the fact (e.g. via configuration) in order to interpret and compare
     * the credentials value.
     *
     * @return the account's credentials verifying the {@link #getPrincipal() identifier}
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