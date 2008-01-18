/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.authc.support;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.Realm;

import java.util.Collection;

/**
 * A <tt>ModularAuthenticationStrategy</tt> implementation assists the {@link ModularRealmAuthenticator} during the
 * log-in process in a pluggable realm (PAM) environment.
 *
 * <p>The <tt>ModularRealmAuthenticator</tt> will consult implementations of this interface on what to do during each
 * interaction with the configured Realms.  This allows a pluggable strategy of whether or not an authentication
 * attempt must be successful for all realms, only 1 or more realms, no realms, etc.
 *
 * @see AllSuccessfulModularAuthenticationStrategy
 * @see AtLeastOneSuccessfulModularAuthenticationStrategy
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public interface ModularAuthenticationStrategy {

    /**
     * Method invoked by the ModularAuthenticator signifying that the authentication process is about to begin for the
     * specified <tt>token</tt> - called before any <tt>Realm</tt> is actually invoked.
     *
     * @param realms the Realms that will be consulted during the authentication process for the specified token.
     * @param token the Principal/Credential representation to be used during authentication for a corresponding subject.
     * @throws AuthenticationException if the strategy implementation does not wish the Authentication attempt to start.
     */
    void beforeAllAttempts( Collection<? extends Realm> realms, AuthenticationToken token ) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just prior to the realm being consulted for account data,
     * allowing pre-authentication-attempt logic for that realm only.
     *
     * @param realm the realm that will be consulted for <tt>Account</tt> for the specified <tt>token</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login
     * process for the associated subject (user) to stop immediately.
     */
    void beforeAttempt( Realm realm, AuthenticationToken token ) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just after the given realm has been consulted for authentication,
     * allowing post-authentication-attempt logic for that realm only.
     * @param realm the realm that was just consulted for <tt>Account</tt> for the given <tt>token</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param account the <tt>Account</tt> object returned by the realm during the consultation process, or
     * <tt>null</tt> if the realm was unable to acquire account data based on the given <tt>token</tt>.
     * @param t the Throwable thrown by the Realm during the attempt, or <tt>null</tt> if the method returned normally.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login process
     * for the associated subject (user) to stop immediately.
     */
    void afterAttempt( Realm realm, AuthenticationToken token, Account account, Throwable t )
        throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator signifying that all of its configured Realms have been consulted
     * for account data, allowing post-proccessing after all realms have completed.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param aggregated the aggregated <tt>Account</tt> instance populated by all realms during the
     * log-in attempt.
     * @throws AuthenticationException if the Strategy implementation wishes to fail the authentication attempt.
     */
    void afterAllAttempts( AuthenticationToken token, Account aggregated ) throws AuthenticationException;
}
