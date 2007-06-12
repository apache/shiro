package org.jsecurity.authc.support;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.Realm;

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
     * Method invoked by the ModularAuthenticator just prior to the realm being consulted for authentication info,
     * allowing pre-authentication-attempt logic for that realm only.
     *
     * @param realm the realm that will be consulted for <tt>AuthenticationInfo</tt> for the specified <tt>token</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login
     * process for the associated subject (user) to stop immediately.
     */
    void beforeAttempt( Realm realm, AuthenticationToken token ) throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator just after the given realm has been consulted for authentication,
     * allowing post-authentication-attempt logic for that realm only.
     * @param realm the realm that was just consulted for <tt>AuthenticationInfo</tt> for the given <tt>token</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param info the <tt>AuthenticationInfo</tt> object returned by the realm during the consultation process, or
     * <tt>null</tt> if the realm was unable to acquire account information based on the given <tt>token</tt>.
     * @param t the Throwable thrown by the Realm during the attempt, or <tt>null</tt> if the method returned normally.
     * @throws AuthenticationException an exception thrown by the Strategy implementation if it wishes the login process
     * for the associated subject (user) to stop immediately.
     */
    void afterAttempt( Realm realm, AuthenticationToken token, AuthenticationInfo info, Throwable t )
        throws AuthenticationException;

    /**
     * Method invoked by the ModularAuthenticator signifying that all of its configured Realms have been consulted
     * for authentication info, allowing post-proccessing after all realms have completed.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted for the subject attempting system log-in.
     * @param aggregated the aggregated <tt>AuthenticationInfo</tt> instance populated by all realms during the
     * log-in attempt.
     * @throws AuthenticationException if the Strategy implementation wishes to fail the authentication attempt.
     */
    void afterAllAttempts( AuthenticationToken token, AuthenticationInfo aggregated ) throws AuthenticationException;
}
