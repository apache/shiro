package org.jsecurity.authc.event.mgt;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface AuthenticationEventManager extends AuthenticationEventFactory, AuthenticationEventSender {

    /**
     * Utility method that first creates a failure event based on the given token and exception and then actually sends
     * the event.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param ae    the <tt>AuthenticationException</tt> that occurred as a result of the attempt.
     */
    void sendFailureEvent(AuthenticationToken token, AuthenticationException ae);

    /**
     * Utility method that first creates a success event based on the given token and account and then actually sends
     * the event.
     *
     * @param token   the authentication token reprenting the subject (user)'s authentication attempt.
     * @param account the <tt>Account</tt> obtained after the successful attempt.
     */
    void sendSuccessEvent(AuthenticationToken token, Account account);

    /**
     * Utility method that first creates a logout event based on the given subjectIdentifier and then actually
     * sends the event.
     *
     * @param subjectPrincipal the application-specific Subject/user identifier.
     */
    void sendLogoutEvent(Object subjectPrincipal);
}
