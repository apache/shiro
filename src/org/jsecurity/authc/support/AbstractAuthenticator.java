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
package org.jsecurity.authc.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.event.*;
import org.jsecurity.util.Initializable;

/**
 * Superclass for almost all {@link Authenticator} implementations that performs the common work around authentication
 * attempts.
 *
 * <p>This class delegates the actual authentication attempt to subclasses but will send events based on a
 * successful or failed attempt.
 *
 * <p>In most cases, the only thing a subclass needs to do (via its {@link #doAuthenticate} implementation)
 * is perform the actual principal/credential verification process for the submitted <tt>AuthenticationToken</tt>.
 *
 * <p>This implementation employs an event-based architecture so other components may react to both failed and
 * successful authentication attempts.  Failure or success events are triggered based on the
 * subclass's {@link #doAuthenticate} implementation throwing an exception or not, respectively.  That is, a failure
 * event will be created and sent if <tt>doAuthenticate</tt> throws an exception a success event will be created and
 * sent if it does not.  The actual events
 * themselves are constructed via an {@link AuthenticationEventFactory} and sent to interested components via a
 * {@link AuthenticationEventSender}.
 * 
 * <p>Both the event factory and the event sender may be set as properties of this class.  A simple default event
 * factory is already provided, but a sender <b>must</b> be set, either by injection or by subclass implementation,
 * if you wish to send AuthenticationEvents.  By omitting an event sender, you are implicitly directing this
 * implementation to disable events.
 *
 * <p>After all class attributes have been set, the {@link #init()}
 * method must be called, either by a framework or explicitly in code, before the AbstractAuthenticator
 * instance can be used.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class AbstractAuthenticator implements Authenticator, AuthenticationEventListenerRegistrar, Initializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log log = LogFactory.getLog(getClass());

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Factory used to create authentication events for publishing.
     */
    private AuthenticationEventFactory authcEventFactory = new SimpleAuthenticationEventFactory();

    /**
     * Sender used to publish authentication events.  The default is null, which means the events
     * are not published.
     */
    private AuthenticationEventSender authcEventSender = null;

    /**
     * Whether or not to fail the authentication process when sending an event (via the sender) and the sender
     * can't send the event (i.e. it throws an exception );  Default is <tt>false</tt> for system-resiliency so that
     * a user can still login even if the event subsystem fails.
     */
    private boolean eventSendErrorFailsAuthentication = false;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AbstractAuthenticator(){}

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Returns the <tt>AuthenticationEventFactory</tt> this <tt>Authenticator</tt> will use to create
     * <tt>AuthenticationEvents</tt> during successful or failed authentication attempts.
     * @return the <tt>AuthenticationEventFactory</tt> this <tt>Authenticator</tt> will use to create
     * <tt>AuthenticationEvents</tt> during successful or failed authentication attempts.
     */
    public AuthenticationEventFactory getAuthenticationEventFactory() {
        return authcEventFactory;
    }

    /**
     * Sets the <tt>AuthenticationEventFactory</tt> this <tt>Authenticator</tt> will use to create
     * <tt>AuthenticationEvents</tt> during successful or failed authentication attempts.
     * @param factory the <tt>AuthenticationEventFactory</tt> this <tt>Authenticator</tt> will use to create
     * <tt>AuthenticationEvents</tt> during successful or failed authentication attempts.
     */
    public void setAuthenticationEventFactory( AuthenticationEventFactory factory ) {
        this.authcEventFactory = factory;
    }

    /**
     * Returns the <tt>AuthenticationEventSender</tt> this Authenticator will use to send <tt>AuthenticationEvent</tt>s
     * to interested parties once an event is created.
     * @return the <tt>AuthenticationEventSender</tt> this Authenticator will use to send <tt>AuthenticationEvent</tt>s
     * to interested parties once an event is created.
     */
    public AuthenticationEventSender getAuthenticationEventSender() {
        return authcEventSender;
    }

    /**
     * Sets the <tt>AuthenticationEventSender</tt> this Authenticator will use to send <tt>AuthenticationEvent</tt>s
     * to interested parties once an event is created.
     * @param authcEventSender the <tt>AuthenticationEventSender</tt> this Authenticator will use to send
     * <tt>AuthenticationEvent</tt>s to interested parties once an event is created.
     */
    public void setAuthenticationEventSender( AuthenticationEventSender authcEventSender ) {
        this.authcEventSender = authcEventSender;
    }

    protected AuthenticationEventSender createAuthenticationEventSender() {
        return new SimpleAuthenticationEventSender();
    }

    protected AuthenticationEventSender ensureAuthenticationEventSender() {
        AuthenticationEventSender sender = getAuthenticationEventSender();
        if ( sender == null ) {
            sender = createAuthenticationEventSender();
            setAuthenticationEventSender( sender );
        }
        return sender;
    }

   private void assertSenderCanRegister() {
       AuthenticationEventSender sender = getAuthenticationEventSender();
       if ( !(sender instanceof AuthenticationEventListenerRegistrar) ) {
           String msg = "The underlying AuthenticationEventSender implementation [" +
                    sender.getClass().getName() + "] does not implement the " +
                    AuthenticationEventListenerRegistrar.class.getName() + " interface and therefore " +
               "AuthenticationEvents cannot be propagated to registered listeners.  Please ensure this " +
               "Authenticator instance is injected with an AuthenticationEventSender that supports this interface " +
               "if you wish to register for AuthenticationEvents.";
            throw new IllegalStateException(msg);
       }
    }

    public void add(AuthenticationEventListener listener) {
        assertSenderCanRegister();
        ((AuthenticationEventListenerRegistrar)getAuthenticationEventSender()).add(listener);
    }

    public boolean remove(AuthenticationEventListener listener) {
        AuthenticationEventSender sender = getAuthenticationEventSender();
        return ( sender instanceof AuthenticationEventListenerRegistrar ) &&
               ((AuthenticationEventListenerRegistrar)sender).remove(listener);
    }

    /**
     * Returns whether or not a problem sending an authentication event causes authentication to fail
     * for the attempting subject.
     *
     * <p>JSecurity employs an event-based architecture to allow components to react when interesting things happen.
     * When a subject's authentication attempt is successful or fails, this Authenticator implementation will use an
     * underlying {@link #setAuthenticationEventSender AuthenticationEventSender} to send the event in either case.
     *
     * <p>If for some reason the event sender throws an exception during the send operation, this property determines
     * whether or not the entire authentication attempt will fail.
     *
     * <p>The default is <b>false</b> for resiliency's sake: an event sending problem does not fail the authentication.
     *
     * @return whether or not a problem sending an authentication event causes the entire authentication process to fail
     * for the attempting subject (user).
     */
    public boolean isEventSendErrorFailsAuthentication() {
        return eventSendErrorFailsAuthentication;
    }

    public void setEventSendErrorFailsAuthentication(boolean eventSendErrorFailsAuthentication) {
        this.eventSendErrorFailsAuthentication = eventSendErrorFailsAuthentication;
    }

    /*-------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Provided for subclass overriding.  Default implementation does nothing..
     */
    public void init() {
        //no-op
    }

    /**
     * Creates an <tt>AuthenticationEvent</tt> in the event of a failed authentication attempt, based on the given
     * authentication token and exception that occurred during the attempt.
     *
     * <p>The default implementation merely delegates creation to the internal {@link AuthenticationEventFactory}
     * property.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param ae the <tt>AuthenticationException</tt> that occurred as a result of the attempt.
     * @return an event that represents the failed attempt.
     */
    protected AuthenticationEvent createFailureEvent( AuthenticationToken token, AuthenticationException ae ) {
        AuthenticationEventFactory factory = getAuthenticationEventFactory();
        return factory.createFailureEvent( token, ae );
    }

    /**
     * Creates an <tt>AuthenticationEvent</tt> in the event of a successful authentication attempt, based on the given
     * authentication token and <tt>Account</tt> that was created as a result of the successful attempt.
     *
     * <p>The default implementation merely delegates creation to the internal {@link AuthenticationEventFactory}
     * property.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param account the <tt>Account</tt> returned by {@link #doAuthenticate} after the successful attempt.
     * @return an event that represents the successful attempt.
     */
    protected AuthenticationEvent createSuccessEvent( AuthenticationToken token, Account account ) {
        AuthenticationEventFactory factory = getAuthenticationEventFactory();
        return factory.createSuccessEvent( token, account );
    }

    /**
     * Utility method that first creates a failure event based on the given token and exception and then actually sends
     * the event.
     *
     * <p>The default implementation does not attempt to create an event if the {@link #setAuthenticationEventSender}
     * property has not been set - the logic is that event creation overhead will not be incurred if it would never
     * be sent.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param ae the <tt>AuthenticationException</tt> that occurred as a result of the attempt.
     */
    protected void sendFailureEvent( AuthenticationToken token, AuthenticationException ae ) {
        AuthenticationEventSender sender = getAuthenticationEventSender();
        //only incur event creation overhead if the event can actually be sent:
        if ( sender != null ) {
            AuthenticationEvent event = createFailureEvent( token, ae );
            if ( event != null ) {
                send( event );
            } else {
                if ( log.isDebugEnabled() ) {
                    log.debug( "No AuthenticationEvent instance returned from " +
                               "'createFailureEvent' method call.  No failed authentication " +
                               "event will be sent." );
                }
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No AuthenticationEventSender configured.  No failure event will " +
                           "be sent" );
            }
        }

    }

    /**
     * Utility method that first creates a success event based on the given token and account and then actually sends
     * the event.
     *
     * <p>The default implementation does not attempt to create an event if the {@link #setAuthenticationEventSender}
     * property has not been set - the logic is that event creation overhead will not be incurred if it would never be
     * sent.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param account the <tt>Account</tt> returned by {@link #doAuthenticate} after the successful attempt.
     */
    protected void sendSuccessEvent( AuthenticationToken token, Account account ) {
        AuthenticationEventSender sender = getAuthenticationEventSender();
        //only incur event creation overhead if the event can actually be sent:
        if ( sender != null ) {
            AuthenticationEvent event = createSuccessEvent( token, account );
            if ( event != null ) {
                try {
                    send( event );
                } catch (Throwable t) {
                    if ( isEventSendErrorFailsAuthentication() ) {
                        String msg = "Unable to send event [" + event + "].  This authenticator is configured to " +
                            "interpret an event sending error as a failure during the authentication process " +
                            "via the setEventSendErrorFailsAuthentication property.  Authentication failed.";
                        throw new AuthenticationException( msg, t );
                    } else {
                        if ( log.isWarnEnabled() ) {
                            String msg = "Unable to send AuthenticationEvent [" + event + "].  Ignoring send error " +
                                "(for system resiliency) and continuing with the authentication process.  Please " +
                                "check your sender configuration and/or implementation.";
                            log.warn( msg, t );
                        }
                    }
                }
            } else {
                if ( log.isDebugEnabled() ) {
                    log.debug( "No AuthenticationEvent instance returned from " +
                            "'createSuccessEvent' method call.  No success " +
                            "event will be sent." );
                }
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No AuthenticationEventSender configured.  No success event will " +
                           "be sent" );
            }
        }
    }

    /**
     * Utility method that will send any type of <tt>AuthenticationEvent</tt> instance.
     *
     * <p>The default implementation merely delegates to the internal {@link AuthenticationEventSender} property if
     * it exists.
     *
     * @param event the <tt>AuthenticationEvent</tt> to send to interested parties.
     * 
     * @throws IllegalArgumentException if the method argument is null
     */
    protected void send( AuthenticationEvent event ) throws IllegalArgumentException {
        if ( event == null ) {
            throw new IllegalArgumentException( "AuthenticationEvent argument cannot be null" );
        }
        AuthenticationEventSender sender = getAuthenticationEventSender();
        if ( sender != null ) {
            sender.send( event );
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No AuthenticationEventSender configured.  Event [" + event + "] will not be sent." );
            }
        }
    }

    

    /**
     * Implementation of the {@link Authenticator} interface that functions in the following manner:
     *
     * <ol>
     * <li>Calls template {@link #doAuthenticate doAuthenticate} method for subclass execution of the actual
     * authentication behavior.</li>
     * <li>If an <tt>AuthenticationException</tt> is thrown during <tt>doAuthenticate</tt>, create and send a
     * failure <tt>AuthenticationEvent</tt> that represents this failure, and then propogate this exception
     * for the caller to handle.</li>
     * <li>If no exception is thrown (indicating a successful login), send a success <tt>AuthenticationEvent</tt>
     * noting the successful authentication.</li>
     * <li>Return the <tt>Account</tt></li>
     * </ol>
     * 
     * @param token the submitted token representing the subject's (user's) login principals and credentials.
     * @return the Account referencing the authenticated user's account data.
     *
     * @throws AuthenticationException if there is any problem during the authentication process - see the
     * interface's JavaDoc for a more detailed explanation.
     */
    public final Account authenticate( AuthenticationToken token )
            throws AuthenticationException {

        if ( token == null ) {
            throw new IllegalArgumentException( "Method argumet (authentication token) cannot be null." );
        }

        if ( log.isTraceEnabled() ) {
            log.trace( "Authentication attempt received for token [" + token + "]" );
        }

        Account account;
        try {
            account = doAuthenticate( token );
            if ( account == null ) {
                String msg = "Authentication token [" + token + "] could not be processed for authentication by this " +
                        "Authenticator instance.  Please check that it is configured correctly.";
                throw new AuthenticationException( msg );
            }
        } catch ( Throwable t ) {
            AuthenticationException ae = null;
            if ( t instanceof AuthenticationException ) {
                ae = (AuthenticationException)t;
            }
            if ( ae == null ) {
                //Exception thrown was not an expected AuthenticationException.  Therefore it is probably a little more
                //severe or unexpected.  So, wrap in an AuthenticationException, log to warn, and propagate:
                String msg = "Authentication failed for token submission [" + token + "].  Possible unexpected " +
                        "error? (Typical or expected login exceptions should extend from AuthenticationException).";
                ae = new AuthenticationException( msg, t );
                if ( log.isWarnEnabled() ) {
                    log.warn( msg, t );
                }
            }
            try {
                sendFailureEvent( token, ae );
            } catch (Throwable t2) {
                String msg = "Unable to send event for failed authentication attempt.  Please check the " +
                        "authenticationEventSender implementation.  Logging sending exception and propagating " +
                        "original AuthenticationException instead...";
                if ( log.isWarnEnabled() ) {
                    log.warn( msg, t2 );
                }
            }

            throw ae;
        }

        if ( log.isInfoEnabled() ) {
            log.info( "Authentication successful for token [" + token + "].  " +
                      "Returned account: [" + account + "]" );
        }

        sendSuccessEvent( token, account);

        return account;
    }

    /**
     * Template design pattern hook for subclasses to implement specific authentication behavior.
     *
     * <p>Common behavior for most authentication attempts is encapsulated in the
     * {@link #authenticate} method and that method invokes this one for custom behavior.
     *
     * <p><b>N.B.</b> Subclasses <em>should</em> throw some kind of
     * <tt>AuthenticationException</tt> if there is a problem during
     * authentication instead of returning <tt>null</tt>.  A <tt>null</tt> return value indicates
     * a configuration or programming error, since <tt>AuthenticationException</tt>s should
     * indicate any expected problem (such as an unknown account or username, or invalid password, etc).
     *
     * @param token the authentication token encapsulating the user's login information.
     * @return an <tt>Account</tt> object encapsulating the user's account information
     * important to JSecurity.
     * @throws AuthenticationException if there is a problem logging in the user.
     */
    protected abstract Account doAuthenticate( AuthenticationToken token )
            throws AuthenticationException;
}