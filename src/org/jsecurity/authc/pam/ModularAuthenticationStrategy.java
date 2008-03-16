/*
 * Copyright 2005-2008 Les Hazlewood
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
package org.jsecurity.authc.pam;

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
     * <p>The <code>Account</code> object returned from this method is essentially an empty place holder for
     * aggregating account data across multiple realms.  It should be populated by the realms over the course of the
     * authentication attempt across the multiple realms.  It will be passed into the
     * {@link #beforeAttempt} calls, allowing inspection of the aggregated account data up to that point in the
     * multi-realm authentication, allowing any logic to be executed accordingly.
     *
     * @param realms the Realms that will be consulted during the authentication process for the specified token.
     * @param token the Principal/Credential representation to be used during authentication for a corresponding subject.
     * @return an empty Account object that will populated with data from multiple realms.
     * @throws AuthenticationException if the strategy implementation does not wish the Authentication attempt to execute.
     */
    Account beforeAllAttempts( Collection<? extends Realm> realms, AuthenticationToken token ) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just prior to the realm being consulted for account data,
     * allowing pre-authentication-attempt logic for that realm only.
     *
     * <p>This method returns an <code>Account</code> object that will be used for further interaction with realms.  Most
     * implementations will merely return the <code>aggregate</code> method argument if they don't have a need to
     * manipulate it.
     *
     * @param realm the realm that will be consulted for <tt>Account</tt> for the specified <tt>token</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param aggregate the aggregated Account object being used across the multi-realm authentication attempt
     * @return the Account object that will be presented to further realms in the authentication process - returning
     *         the <code>aggregate</code> method argument is the normal case if no special action needs to be taken.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login
     * process for the associated subject (user) to stop immediately.
     */
    Account beforeAttempt( Realm realm, AuthenticationToken token, Account aggregate ) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just after the given realm has been consulted for authentication,
     * allowing post-authentication-attempt logic for that realm only.
     *
     * <p>This method returns an <code>Account</code> object that will be used for further interaction with realms.  Most
     * implementations will merge the <code>singleRealmAccount</code> into the <code>aggregateAccount</code> and
     * just return the <code>aggregateAccount</code> for continued use throughout the authentication process.</p>
     * 
     * @param realm the realm that was just consulted for <tt>Account</tt> for the given <tt>token</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param singleRealmAccount the <tt>Account</tt> object returned by the realm during the consultation process, or
     * <tt>null</tt> if the realm was unable to acquire account data based on the given <tt>token</tt>.
     * @param aggregateAccount the Account object being populated with data across multiple realms.
     * @param t the Throwable thrown by the Realm during the attempt, or <tt>null</tt> if the method returned normally.
     * @return the Account object that will be presented to further realms in the authentication process - returning
     *         the <code>aggregateAccount</code> method argumen is the normal case if no special action needs to be taken.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login process
     * for the associated subject (user) to stop immediately.
     */
    Account afterAttempt( Realm realm, AuthenticationToken token, Account singleRealmAccount, Account aggregateAccount, Throwable t )
        throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator signifying that all of its configured Realms have been consulted
     * for account data, allowing post-proccessing after all realms have completed.
     *
     * <p>Returns the final Account object that will be returned from the Authenticator to the authenticate() caller.
     * This is most likely the aggregate Account object that has been populated by many realms, but the actual return value is
     * always up to the implementation.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param aggregate the aggregate <tt>Account</tt> instance populated by all realms during the log-in attempt.
     * @return the final <code>Account</code> object to return to the Authenticator.authenticate() caller.
     * @throws AuthenticationException if the Strategy implementation wishes to fail the authentication attempt.
     */
    Account afterAllAttempts( AuthenticationToken token, Account aggregate ) throws AuthenticationException;
}
