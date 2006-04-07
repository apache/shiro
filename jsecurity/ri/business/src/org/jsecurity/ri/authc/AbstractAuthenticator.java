/*
 * Copyright (C) 2005 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.ri.authc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.authc.event.AuthenticationEventFactory;
import org.jsecurity.ri.authc.event.AuthenticationEventSender;
import org.jsecurity.ri.authc.event.SimpleAuthenticationEventFactory;
import org.jsecurity.ri.authz.AuthorizationContextFactory;
import org.jsecurity.ri.authz.support.SimpleAuthorizationContextFactory;

/**
 * Superclass for {@link Authenticator} implementations that performs the common work
 * of wrapping a returned {@link AuthorizationContext} using an {@link AuthorizationContextFactory}
 * and binding the context using an {@link AuthorizationContextBinder}.  Subclasses should
 * implement the {@link #doAuthenticate(org.jsecurity.authc.AuthenticationToken)} method.
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
     * Commons logger.
     */
    protected Log log = LogFactory.getLog( getClass() );
    /** Alias for the 'log' protected class attribute for subclass authors that may prefer one over the other. */
    protected Log logger = log;

    /**
     * The factory used to wrap authorization context after authentication.
     */
    private AuthorizationContextFactory authContextFactory = new SimpleAuthorizationContextFactory();

    /**
     * The binder used to bind the authorization context so that it is accessible on subsequent
     * requests.
     */
    private AuthorizationContextBinder authzCtxBinder = new ThreadLocalAuthorizationContextBinder();

    private AuthenticationEventFactory authcEventFactory = new SimpleAuthenticationEventFactory();

    private AuthenticationEventSender authcEventSender = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    protected AuthorizationContextFactory getAuthorizationContextFactory() {
        return authContextFactory;
    }


    public void setAuthorizationContextFactory(AuthorizationContextFactory authContextFactory) {
        this.authContextFactory = authContextFactory;
    }


    public AuthorizationContextBinder getAuthorizationContextBinder() {
        return authzCtxBinder;
    }


    public void setAuthorizationContextBinder(AuthorizationContextBinder authContextBinder) {
        this.authzCtxBinder = authContextBinder;
    }

    public AuthenticationEventFactory getAuthenticationEventFactory() {
        return authcEventFactory;
    }

    public void setAuthenticationEventFactory( AuthenticationEventFactory factory ) {
        this.authcEventFactory = factory;
    }

    public AuthenticationEventSender getAuthenticationEventSender() {
        return authcEventSender;
    }

    public void setAuthenticationEventSender( AuthenticationEventSender authcEventSender ) {
        this.authcEventSender = authcEventSender;
    }

    protected AuthenticationEvent createFailureEvent( AuthenticationToken token, AuthenticationException ae ) {
        AuthenticationEventFactory factory = getAuthenticationEventFactory();
        return factory.createFailureEvent( token, ae );
    }

    protected AuthenticationEvent createSuccessEvent( AuthenticationToken token, AuthenticationInfo info ) {
        AuthenticationEventFactory factory = getAuthenticationEventFactory();
        return factory.createSuccessEvent( token, info );
    }

    protected void sendFailureEvent( AuthenticationToken token, AuthenticationException ae ) {
        AuthenticationEvent event = createFailureEvent( token, ae );
        if ( event != null ) {
            send( event );
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No AuthenticationEvent instance returned from 'createFailureEvent' method call.  " +
                    "No failed authentication event will be sent." );
            }
        }
    }

    protected void sendSuccessEvent( AuthenticationToken token, AuthenticationInfo info ) {
        AuthenticationEvent event = createSuccessEvent( token, info );
        if ( event != null ) {
            send( event );
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No AuthenticationEvent instance returned from 'createSuccessEvent' method call.  " +
                    "No successful authentication event will be sent." );
            }
        }
    }

    protected void send( AuthenticationEvent event ) throws IllegalArgumentException {
        if ( event == null ) {
            throw new IllegalArgumentException( "AuthenticationEvent argument cannot be null" );
        }
        AuthenticationEventSender sender = getAuthenticationEventSender();
        if ( sender != null ) {
            sender.send( event );
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No AuthenticationEventSender configured.  Event [" + event + "] will not " +
                    "be sent." );
            }
        }
    }

    protected AuthorizationContext createAuthorizationContext( AuthenticationInfo info ) {
        return getAuthorizationContextFactory().createAuthorizationContext( info );
    }

    protected void bind( AuthorizationContext authzCtx ) {
        getAuthorizationContextBinder().bindAuthorizationContext( authzCtx );
    }

    private void assertCreation( AuthorizationContext authzCtx ) throws IllegalStateException {
        if ( authzCtx == null ) {
            String msg = "Programming or configuration error - No AuthorizationContext was created after successful " +
                "authentication.  Verify that you have either configured the " + getClass().getName() +
                " instance with a proper " + AuthorizationContextFactory.class.getName() + " (easier) or " +
                "that you have overridden the " + AbstractAuthenticator.class.getName() +
                ".createAuthorizationContext( AuthenticationInfo info ) method.";
            throw new IllegalStateException( msg );
        }
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public final AuthorizationContext authenticate( AuthenticationToken token ) throws AuthenticationException {

        if (log.isInfoEnabled()) {
            log.info("Authentication request received for token [" + token + "]");
        }

        AuthenticationInfo info;
        try {
            info = doAuthenticate( token );
            if( info == null ) {
                throw new AuthenticationException( "Authentication token of type [" + token.getClass() + "] " +
                    "could not be authenticated.  Check that the Authenticator is configured correctly." );
            }
        } catch (AuthenticationException e) {
            // Catch exception for debugging
            if (log.isDebugEnabled()) {
                log.debug("Authentication failed for token [" + token + "]", e);
            }

            sendFailureEvent( token, e );

            throw e;
        }

        if (log.isDebugEnabled()) {
            log.debug("Authentication successful.  Returned authentication info: [" + info + "]");
        }

        AuthorizationContext authzCtx = createAuthorizationContext( info );

        assertCreation( authzCtx );

        bind( authzCtx );

        sendSuccessEvent( token, info );

        return authzCtx;
    }

    protected abstract AuthenticationInfo doAuthenticate( AuthenticationToken token ) throws AuthenticationException;
}