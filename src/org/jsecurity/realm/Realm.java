/*
 * Copyright (C) 2005-2007 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.realm;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.AuthorizationOperations;

/**
 * A <tt>Realm</tt> is a security component that can access application-specific security entities
 * such as users, roles, and permissions to determine authentication and authorization data.
 *
 * <p><tt>Realm</tt>s usually have a 1-to-1 correspondance with a datasource such as a relational database,
 * file sysetem, or other similar resource.  As such, implementations of this interface use datasource-specific APIs to
 * determine authorization information, such as JDBC, File IO, Hibernate or JPA, or any other Data Access API.
 *
 * <p>Because most of these datasources usually contain subject (user) information such as usernames and passwords,
 * a Realm can act
 * as a pluggable authentication module in a PAM configuration.  This allows a Realm to perform <i>both</i>
 * authentication and authorization duties for a single datasource, which caters to 90% of the use cases of most
 * applications.  If for some reason you don't want your Realm implementation to perform authentication duties, you
 * should override the {@link #supports(Class)} method to always return <tt>false</tt>.
 *
 * <p>Because every application is different, security data such as users and roles can be
 * represented in any number of ways.  JSecurity tries to
 * maintain a non-intrusive development philosophy whenever possible - it does not require you to
 * implement or extend any <tt>User</tt>, <tt>Group</tt> or <tt>Role</tt> interfaces or classes.
 *
 * <p>Instead, JSecurity allows applications to implement this interface to access
 * environment-specific datasources and data model objects.  The implementation can then be
 * plugged in to the application's JSecurity configuration.  This modular technique abstracts
 * away any environment/modeling details and allows JSecurity to be deployed in
 * practically any application environment.
 *
 * <p>Most users will not implement the <tt>Realm</tt> interface directly, but will extend
 * one of the subclasses, {@link org.jsecurity.realm.support.AbstractRealm} or
 * {@link org.jsecurity.realm.support.AbstractCachingRealm},
 * which reduce the tedious methods required to implement a <tt>Realm</tt> from scratch.</p>
 *
 * @see Realm
 * @see org.jsecurity.authc.support.ModularRealmAuthenticator ModularRealmAuthenticator
 * @see org.jsecurity.realm.support.AbstractRealm
 * @see org.jsecurity.realm.support.AbstractCachingRealm
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface Realm extends AuthorizationOperations {

    /**
     * Returns the name of this Realm used to uniquely identify it within the application.
     * This name must be unique amongst all realms used within this security context.
     * @return the unique identifier for this realm.
     */
    String getName();


    /**
     * Returns true if this realm can authenticate subjects with
     * {@link org.jsecurity.authc.AuthenticationToken AuthenticationToken} instances of the specified Class,
     * false otherwise.
     *
     * <p>If the realm does not support the specified type, it will not be used to authenticate any
     * tokens of that type.
     *
     * @param authenticationTokenClass the <tt>AuthenticationToken</tt> Class to check for support.
     *
     * @return true if this realm can authenticate subjects represented by tokens of the
     * specified class, false otherwise.
     */
    boolean supports( Class authenticationTokenClass );

    /**
     * Returns account information for the account associated with the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     *
     * @param token the application-specific representation of an account principal and credentials.
     *
     * @return the account information for the account associated with the specified <tt>token</tt>,
     * or <tt>null</tt> if no account could be found based on the <tt>token</tt>.
     *
     * @throws org.jsecurity.authc.AuthenticationException if there is an error obtaining obtaining or
     * constructing an AuthenticationInfo based on the specified <tt>token</tt>.
     */
    AuthenticationInfo getAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException;

}