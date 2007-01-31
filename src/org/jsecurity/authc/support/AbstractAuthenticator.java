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
import org.jsecurity.SecurityManager;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.AuthenticationEventFactory;
import org.jsecurity.authc.event.AuthenticationEventSender;
import org.jsecurity.authc.event.support.SimpleAuthenticationEventFactory;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.bind.SecurityContextBinder;
import org.jsecurity.context.bind.support.ThreadLocalSecurityContextBinder;
import org.jsecurity.context.factory.SecurityContextFactory;
import org.jsecurity.context.factory.support.DelegatingSecurityContextFactory;

/**
 * Superclass for almost all {@link Authenticator} implementations that performs the common work around authentication
 * attempts.
 *
 * <p>This class delegates the actual authentication attempt to subclasses but will send events based on a
 * successful or failed attempt, create a {@link SecurityContext SecurityContext} in the event of a successful attmept,
 * and bind this <tt>SecurityContext</tt> to the application for further use.
 *
 * <p>In most cases, the only thing a subclass needs to do (via its {@link #doAuthenticate} implementation)
 * is perform the actual principal/credential verification process for the submitted <tt>AuthenticationToken</tt>.
 *
 * <p>Failure or success events are triggered based on {@link #doAuthenticate} throwing an exception or not,
 * respectively.  The actual events themselves are constructed via an {@link AuthenticationEventFactory} and sent
 * to interested parties via a {@link AuthenticationEventSender}, both of which may be set as properties of this class
 * (instead of overriding this class for event creation and sending).
 *
 * <p>After a successful login attempt, <tt>SecurityContext</tt>s are also created via a {@link SecurityContextFactory}.
 * This may also be set as a property of this class to avoid overriding this class if desired.
 *
 * <p>Once a <tt>SecurityContext</tt> is created for authenticated subject, it is <em>bound</em> to the application for
 * later access in an application-specific manner (thread-local, http cookie, etc).  This binding is performed by this 
 * class via a default thread-local {@link SecurityContextBinder}, which also may be overridden as a
 * {@link #setSecurityContextBinder class property}.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class AbstractAuthenticator implements Authenticator {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    /**
     * The factory used to wrap authorization context after authentication.
     */
    private SecurityContextFactory securityContextFactory = null;

    /**
     * The binder used to bind the authorization context so that it is accessible on subsequent
     * requests.
     */
    private SecurityContextBinder securityContextBinder = new ThreadLocalSecurityContextBinder();

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
     * Used to initialize the default authorization context factory.
     */
    private SecurityManager SecurityManager = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AbstractAuthenticator(){}

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Returns the <tt>SecurityContextFactory</tt> that this Authenticator will use to create a <tt>SecurityContext</tt>
     * upon a successful authentication attempt.
     * @return the <tt>SecurityContextFactory</tt> that this Authenticator will use to create a <tt>SecurityContext</tt>
     * upon a successful authentication attempt.
     *
     * @see #setSecurityContextFactory #setSecurityContextFactory for more explanation.
     */
    protected SecurityContextFactory getSecurityContextFactory() {
        return securityContextFactory;
    }


    /**
     * Sets the <tt>SecurityContextFactory</tt> that this Authenticator will use to create a <tt>SecurityContext</tt>
     * upon a successful authentication attempt.
     *
     * <p>It is not recommended to override this property, but instead set the
     * {@link #setSecurityManager SecurityManager} property.  When a <tt>SecurityManager</tt> property is set, this class will
     * use it to construct an internal {@link DelegatingSecurityContextFactory DelegatingSecurityContextFactory}, which
     * uses the SecurityManager in a more efficient manner.
     *
     * @param securityContextFactory the <tt>SecurityContextFactory</tt> that this Authenticator will use to create a
     * <tt>SecurityContext</tt> upon a successful authentication attempt.
     */
    public void setSecurityContextFactory( SecurityContextFactory securityContextFactory ) {
        this.securityContextFactory = securityContextFactory;
    }


    /**
     * Returns the <tt>SecurityContextBinder</tt> this <tt>Authenticator</tt> will use to <em>bind</em> a subject's
     * <tt>SecurityContext</tt> to the application for later use.
     * @return the <tt>SecurityContextBinder</tt> this <tt>Authenticator</tt> will use to <em>bind</em> a subject's
     * <tt>SecurityContext</tt> to the application for later use.
     *
     * @see #setSecurityContextBinder #setSecurityContextBinder for more explanation.
     */
    public SecurityContextBinder getSecurityContextBinder() {
        return securityContextBinder;
    }

    /**
     * Sets the <tt>SecurityContextBinder</tt> this <tt>Authenticator</tt> will use to <em>bind</em> a subject's
     * <tt>SecurityContext</tt> to the application for later use.
     *
     * <p>The default implementation used by this class is a
     * {@link ThreadLocalSecurityContextBinder ThreadLocalSecurityContextBinder} and probably shouldn't be overridden
     * in server-side applications such as Web or EJB apps unless you know what you are doing.
     *
     * <p>This property probably <b><em>will</em></b> however probably need to be changed if in a standalone
     * client environment, such as in an Applet or Java Web Start application, where the <tt>SecurityContext</tt> will
     * need to be accessible in a well-known location such as in a static memory variable (less desireable), or in
     * a better managed application context (e.g. Spring or Pico - more desireable).
     *
     * @param securityContextBinder the <tt>SecurityContextBinder</tt> this <tt>Authenticator</tt> will use to
     * <em>bind</em> a subject's <tt>SecurityContext</tt> to the application for later use.
     */
    public void setSecurityContextBinder( SecurityContextBinder securityContextBinder ) {
        this.securityContextBinder = securityContextBinder;
    }

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

    /**
     * Sets the SecurityManager that will be used to construct and set this class's <tt>SecurityContextFactory</tt>
     * property if one is not explicitly set via the {@link #setSecurityContextFactory} method.
     *
     * <p>It <b>IS</b> recommended that most configurations set this <tt>SecurityManager</tt> property and
     * <b><em>NOT</em></b> explicitly set the <tt>SecurityContextFactory</tt> property unless you know what you're
     * doing and/or need special behavior.
     * 
     * @param SecurityManager the SecurityManager that will be used to construct an internal <tt>SecurityContextFactory</tt>.
     */
    public void setSecurityManager(SecurityManager SecurityManager) {
        this.SecurityManager = SecurityManager;
    }


    /*-------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    /**
     * Public initializer that should be called after all class properties have been set, but before the instance
     * is used to process authentications.
     */
    public void init() {
        if( getSecurityContextFactory() == null ) {
            if( SecurityManager == null ) {
                throw new IllegalStateException( "If an authorization context factory is not injected, a realm manager must be " +
                    "provided so that the default " + DelegatingSecurityContextFactory.class.getName() +
                    " factory can be initialized." );
            }
            setSecurityContextFactory( new DelegatingSecurityContextFactory( SecurityManager ) );
        }
        onInit();
    }

    /**
     * Subclass template hook to allow subclasses additional initialization behavior without having to override the
     * {@link #init init()} method.
     */
    protected void onInit(){}

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
    protected AuthenticationEvent createFailureEvent( AuthenticationToken token,
                                                      AuthenticationException ae ) {
        AuthenticationEventFactory factory = getAuthenticationEventFactory();
        return factory.createFailureEvent( token, ae );
    }

    /**
     * Creates an <tt>AuthenticationEvent</tt> in the event of a successful authentication attempt, based on the given
     * authentication token and <tt>AuthenticationInfo</tt> that was created as a result of the successful attempt.
     *
     * <p>The default implementation merely delegates creation to the internal {@link AuthenticationEventFactory}
     * property.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param info the <tt>AuthenticationInfo</tt> returned by {@link #doAuthenticate} after the successful attempt.
     * @return an event that represents the successful attempt.
     */
    protected AuthenticationEvent createSuccessEvent( AuthenticationToken token,
                                                      AuthenticationInfo info ) {
        AuthenticationEventFactory factory = getAuthenticationEventFactory();
        return factory.createSuccessEvent( token, info );
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
                if ( logger.isDebugEnabled() ) {
                    logger.debug( "No AuthenticationEvent instance returned from " +
                               "'createFailureEvent' method call.  No failed authentication " +
                               "event will be sent." );
                }
            }
        } else {
            if ( logger.isTraceEnabled() ) {
                logger.trace( "No AuthenticationEventSender configured.  No failure event will " +
                           "be sent" );
            }
        }

    }

    /**
     * Utility method that first creates a success event based on the given token and info and then actually sends
     * the event.
     *
     * <p>The default implementation does not attempt to create an event if the {@link #setAuthenticationEventSender}
     * property has not been set - the logic is that event creation overhead will not be incurred if it would never be
     * sent.
     *
     * @param token the authentication token reprenting the subject (user)'s authentication attempt.
     * @param info the <tt>AuthenticationInfo</tt> returned by {@link #doAuthenticate} after the successful attempt.
     */
    protected void sendSuccessEvent( AuthenticationToken token, AuthenticationInfo info ) {
        AuthenticationEventSender sender = getAuthenticationEventSender();
        //only incur event creation overhead if the event can actually be sent:
        if ( sender != null ) {
            AuthenticationEvent event = createSuccessEvent( token, info );
            if ( event != null ) {
                send( event );
            } else {
                if ( logger.isDebugEnabled() ) {
                    logger.debug( "No AuthenticationEvent instance returned from " +
                            "'createSuccessEvent' method call.  No successful authentication " +
                            "event will be sent." );
                }
            }
        } else {
            if ( logger.isTraceEnabled() ) {
                logger.trace( "No AuthenticationEventSender configured.  No success event will " +
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
            try {
                sender.send( event );
            } catch ( Throwable t ) {
                if ( logger.isWarnEnabled() ) {
                    logger.warn( "Unable to send AuthenticationEvent [" + event + "]", t );
                }
            }
        } else {
            if ( logger.isTraceEnabled() ) {
                logger.trace( "No AuthenticationEventSender configured.  Event [" + event + "] will " +
                        "not be sent." );
            }
        }
    }

    /**
     * Creates a <tt>SecurityContext</tt> instance for the user represented by the given method argument.
     *
     * <p>The default implementation delegates to the internal {@link SecurityContextFactory} property.
     *
     * @param info the <tt>AuthenticationInfo</tt> of a newly authenticated subject/user.
     * @return the <tt>SecurityContext</tt> that represents the authorization and session data for the newly
     * authenticated subject/user.
     */
    protected SecurityContext createSecurityContext( AuthenticationInfo info ) {
        SecurityContextFactory factory = getSecurityContextFactory();
        if( factory == null ) {
            throw new IllegalStateException(
                    "No security context factory is configured, so authentication cannot " +
                    "be completed.  Make sure the init() method is being called on the " +
                    "authenticator before it is used." );
        }

        return factory.createSecurityContext( info );
    }

    /**
     * Binds a <tt>SecurityContext</tt> instance created after authentication to the application for later use.
     *
     * <p>The default implementation merely delegates to the internal {@link SecurityContextBinder} property.
     *
     * @param secCtx the <tt>SecurityContext</tt> instance created after authentication to be bound to the application
     * for later use.
     */
    protected void bind( SecurityContext secCtx ) {
        getSecurityContextBinder().bindSecurityContext( secCtx );
    }

    private void assertCreation( SecurityContext secCtx ) throws IllegalStateException {
        if ( secCtx == null ) {
            String msg = "Programming or configuration error - No SecurityContext was created after successful " +
                    "authentication.  Verify that you have either configured the " + getClass().getName() +
                    " instance with a proper " + SecurityContextFactory.class.getName() + " (easier) or " +
                    "that you have overridden the " + AbstractAuthenticator.class.getName() +
                    ".createSecurityContext( AuthenticationInfo info ) method.";
            throw new IllegalStateException( msg );
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
     * <li>If no exception is thrown (indicating a successful login), perform the following:
     *     <ol>
     *         <li>{@link #createSecurityContext Create a <tt>SecurityContext</tt>} instance that represents the
     *             <tt>AuthenticationInfo</tt> returned by <tt>doAuthenticate</tt></li>
     *         <li>{@link #bind Bind this newly created SecurityContext} to the application such that it can be
     *             referenced by the application later.</li>
     *         <li>Create and send a success <tt>AuthenticationEvent</tt> noting the successful authentication.</li>
     *         <li>Return the newly created <tt>SecurityContext</tt> to the caller should they wish to use it
     *             immediately.</li>
     *     </ol>
     * </li>
     * </ol>
     * @param token the submitted token representing the subject's (user's) login principals and credentials.
     * @return the SecurityContext referencing the authenticated user's access rights.
     *
     * @throws AuthenticationException if there is any problem during the authentication process - see the
     * interface's JavaDoc for a more detailed explanation.
     */
    public final SecurityContext authenticate( AuthenticationToken token )
            throws AuthenticationException {

        if ( logger.isTraceEnabled() ) {
            logger.trace( "Authentication request received for token [" + token + "]" );
        }

        AuthenticationInfo info;
        try {
            info = doAuthenticate( token );
            if ( info == null ) {
                throw new AuthenticationException( "Authentication token of type [" +
                    token.getClass() + "] could not be processed for authentication.  Check that " +
                    "the Authenticator is configured correctly." );
            }
        } catch ( AuthenticationException e ) {
            if ( logger.isInfoEnabled() ) {
                logger.info( "Authentication failed for token submission [" + token + "] because [" + e.getMessage() + "]" );
            }
            sendFailureEvent( token, e );
            throw e;
        }

        if ( logger.isInfoEnabled() ) {
            logger.info( "Authentication successful.  Returned authentication info: [" + info + "]" );
        }

        SecurityContext secCtx = createSecurityContext( info );

        assertCreation( secCtx );

        bind( secCtx );

        sendSuccessEvent( token, info );

        return secCtx;
    }

    /**
     * Template design pattern hook for subclasses to implement specific authentication behavior.
     *
     * <p>Common behavior for most all common authentication attempts is encapsulated in the 
     * {@link #authenticate} method and that method invokes this one for custom behavior.
     *
     * <p><b>N.B.</b> Subclasses <em>should</em> throw some kind of
     * <tt>AuthenticationException</tt> if there is a problem during
     * authentication instead of returning <tt>null</tt>.  A <tt>null</tt> return value indicates
     * a configuration or programming error, since <tt>AuthenticationException</tt>s should
     * indicate any expected problem.
     *
     * @param token the authentication token encapsulating the user's login information.
     * @return an <tt>AuthenticationInfo</tt> object encapsulating the user's account information
     * important to JSecurity.  <tt>null</tt> should <em>not</em> be returned.
     * @throws AuthenticationException if there is a problem logging in the user.
     */
    protected abstract AuthenticationInfo doAuthenticate( AuthenticationToken token )
            throws AuthenticationException;
}