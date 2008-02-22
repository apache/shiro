package org.jsecurity.authc.event;

import org.jsecurity.authc.AuthenticationToken;

/**
 * An <tt>AuthenticationEvent</tt> generated in response to an authentication attempt.
 *
 * <p>Its subclasses provide more information as to if the attempt was successful or not and related data in either
 * case</p>
 *
 * <p>The <tt>AuthenticationToken</tt> that was submitted during the authentication attempt that caused this
 * event to be generated is accessible via the {@link #getToken() getToken()} method.</p>
 *
 * @see SuccessfulAuthenticationEvent
 * @see FailedAuthenticationEvent
 *
 * @since 0.9
 */
public abstract class AttemptedAuthenticationEvent extends AuthenticationEvent {

    protected final AuthenticationToken token; //authentication token submitted during the authentication attempt.

    /**
     * Creates a new event triggered during an authentication attempt based on the submitted
     * <tt>AuthenticationToken</tt>.
     * @param token the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     */
    public AttemptedAuthenticationEvent( AuthenticationToken token ) {
        super( token.getPrincipal() );
        this.token = token;
    }


    /**
     * Creates a new authentication event with the given source and the given <tt>AuthenticationToken</tt> submitted
     * during the authentication attempt.
     *
     * @param token the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     * @param source the component responsible for generating the event.
     * associated with the authentication attempt
     */
    public AttemptedAuthenticationEvent( AuthenticationToken token, Object source ) {
        super( source );
        if ( token == null ) {
            String msg = "AuthenticationToken argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
        this.principals = token.getPrincipal();
        this.token = token;
    }

    /**
     * Returns the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     * @return the <tt>AuthenticationToken</tt> submitted during the authentication attempt that triggered this event.
     */
    public AuthenticationToken getToken() {
        return this.token;
    }

}
