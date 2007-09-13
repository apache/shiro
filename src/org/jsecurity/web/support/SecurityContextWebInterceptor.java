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
package org.jsecurity.web.support;

import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.context.support.InvalidSecurityContextException;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebInterceptor;
import org.jsecurity.web.WebStore;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.net.InetAddress;
import java.util.List;

/**
 * Builds a {@link org.jsecurity.context.SecurityContext SecurityContext} based on a web request and makes it
 * accessible via the {@link ThreadContext}.
 * 
 * <p>Consolidates common behaviors in obtaining a SecurityContext in different
 * web environments (e.g. Servlet Filters, framework specific interceptors, etc).
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class SecurityContextWebInterceptor extends SecurityWebSupport implements WebInterceptor {

    /**
     * The key that is used to store subject principals in the session.
     */
    public static final String PRINCIPALS_SESSION_KEY =
        SecurityContextWebInterceptor.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /**
     * The key that is used to store whether or not the user is authenticated in the session.
     */
    public static final String AUTHENTICATED_SESSION_KEY =
        SecurityContextWebInterceptor.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    protected SecurityManager securityManager = null;

    protected SessionWebInterceptor sessionWebInterceptor = null;

    /**
     * Determines whether or not to use the HttpSession as the storage mechanism for principals or the JSecurity
     * Session.  The default is <tt>false</tt>, since JSecurity sessions can be accessed across multiple client
     * mediums (more flexible) and HttpSessions cannot.
     */
    protected boolean preferHttpSessionStorage = false;

    //passthrough attributes to the underlying DefaultWebSessionFactory
    protected WebStore<Serializable> sessionIdStore = null;
    protected WebStore<List> principalsStore = null;
    protected WebStore<Boolean> authenticatedStore = null;
    protected boolean requireSessionOnRequest = false;

    public SecurityContextWebInterceptor() {
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager( SecurityManager securityManager ) {
        this.securityManager = securityManager;
    }

    public boolean isPreferHttpSessionStorage() {
        return preferHttpSessionStorage;
    }

    public void setPreferHttpSessionStorage( boolean preferHttpSessionStorage ) {
        this.preferHttpSessionStorage = preferHttpSessionStorage;
    }

    public WebStore<Serializable> getSessionIdStore() {
        return sessionIdStore;
    }

    public void setSessionIdStore( WebStore<Serializable> sessionIdStore ) {
        this.sessionIdStore = sessionIdStore;
    }

    public WebStore<List> getPrincipalsStore() {
        return principalsStore;
    }

    public void setPrincipalsStore( WebStore<List> principalsStore ) {
        this.principalsStore = principalsStore;
    }

    public WebStore<Boolean> getAuthenticatedStore() {
        return authenticatedStore;
    }

    public void setAuthenticatedStore( WebStore<Boolean> authenticatedStore ) {
        this.authenticatedStore = authenticatedStore;
    }

    public boolean isRequireSessionOnRequest() {
        return requireSessionOnRequest;
    }

    public void setRequireSessionOnRequest( boolean requireSessionOnRequest ) {
        this.requireSessionOnRequest = requireSessionOnRequest;
    }

    protected SessionWebInterceptor getSessionWebInterceptor() {
        return sessionWebInterceptor;
    }

    protected void setSessionWebInterceptor( SessionWebInterceptor sessionWebInterceptor ) {
        this.sessionWebInterceptor = sessionWebInterceptor;
    }

    protected void ensurePrincipalsStore() {
        if ( getPrincipalsStore() == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Initializing default Principals WebStore..." );
            }
            AbstractWebStore<List> store = null;
            if ( isPreferHttpSessionStorage() ) {
                store = new HttpSessionStore<List>( PRINCIPALS_SESSION_KEY, false );
            } else {
                store = new SessionStore<List>( PRINCIPALS_SESSION_KEY, false );
            }
            store.init();
            setPrincipalsStore( store );
        }
    }

    protected void ensureAuthenticatedStore() {
        if ( getAuthenticatedStore() == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Initializing default Authenticated token WebStore..." );
            }
            AbstractWebStore<Boolean> store = null;
            if ( isPreferHttpSessionStorage() ) {
                store = new HttpSessionStore<Boolean>( AUTHENTICATED_SESSION_KEY, false );
            } else {
                store = new SessionStore<Boolean>( AUTHENTICATED_SESSION_KEY, false );
            }
            store.init();
            setAuthenticatedStore( store );
        }
    }

    public void init() {
        SecurityManager securityManager = getSecurityManager();
        if ( securityManager == null ) {
            String msg = "SecurityManager property must be set.";
            throw new IllegalStateException( msg );
        }
        if ( getSessionWebInterceptor() == null ) {
            if ( log.isDebugEnabled() ) {
                log.debug( "Initializing default SessionWebInterceptor instance..." );
            }
            SessionWebInterceptor swi = new SessionWebInterceptor();
            swi.setSessionFactory( securityManager );
            swi.setRequireSessionOnRequest( isRequireSessionOnRequest() );

            WebStore<Serializable> sessionIdStore = getSessionIdStore();
            if ( sessionIdStore != null ) {
                swi.setIdStore( sessionIdStore );
            }

            swi.init();
            setSessionWebInterceptor( swi );
        }

        ensurePrincipalsStore();
        ensureAuthenticatedStore();
    }

    @SuppressWarnings( "unchecked" )
    protected List getPrincipals( ServletRequest servletRequest, ServletResponse servletResponse ) {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        return getPrincipalsStore().retrieveValue( request, response );
    }

    protected boolean isAuthenticated( ServletRequest servletRequest, ServletResponse servletResponse ) {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;
        Boolean value = getAuthenticatedStore().retrieveValue( request, response );
        return value != null && value;
    }

    protected SecurityContext createSecurityContext( List principals, boolean authenticated,
                                                     InetAddress inetAddress, Session session,
                                                     SecurityManager securityManager ) {
        return new DelegatingSecurityContext( principals, authenticated, inetAddress, session, securityManager );
    }

    protected SecurityContext createSecurityContext( ServletRequest request,
                                                     ServletResponse response,
                                                     List principals,
                                                     boolean authenticated,
                                                     Session existing ) {
        SecurityContext securityContext;

        SecurityManager securityManager = getSecurityManager();

        if ( securityManager == null ) {
            final String message = "the SecurityManager attribute must be configured.  This could be " +
                "done by calling setSecurityManager() on the " + getClass().getName() + " instance, or by subclassing " +
                "to retrieve the SecurityManager from an application framework.";
            throw new IllegalStateException( message );
        }

        securityContext = createSecurityContext( principals, authenticated, ThreadContext.getInetAddress(), existing, securityManager );

        return securityContext;
    }


    public SecurityContext createSecurityContext( ServletRequest request, ServletResponse response, Session existing ) {
        List principals = getPrincipals( request, response );
        boolean authenticated = isAuthenticated( request, response );
        return createSecurityContext( request, response, principals, authenticated, existing );
    }

    protected void bindForSubsequentRequests( HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext ) {
        getPrincipalsStore().storeValue( securityContext.getAllPrincipals(), request, response );
        getAuthenticatedStore().storeValue( securityContext.isAuthenticated(), request, response );
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {

        //useful for a number of JSecurity components - do it in case this interceptor is the only one configured:
        bindInetAddressToThread( request );

        //enable the Session if one is associated w/ the request.  This will bind it to the ThreadContext as well.
        SessionWebInterceptor sessionInterceptor = getSessionWebInterceptor();
        if ( sessionInterceptor == null ) {
            String msg = "SessionWebInterceptor property must be set.  This is done by default during the init() " +
                "method.  Please ensure init() is called before using this instance.";
            throw new IllegalStateException( msg );
        }
        sessionInterceptor.preHandle( request, response );

        //bind a dummy SecurityContext to the thread just to support any components that require it.  This is primarily
        //only here to make any existing session available to the createSecurityContext methods (and child methods)
        //via SecurityContext.getSession() in case it is needed.  This isn't very 'clean' per se, but it does prevent
        //any children components (such as WebStores) from knowing about thread locals, which I think is 'cleaner'
        //overall - Les.
        Session session = getSession( request, response );
        SecurityContext dummy =
            new DelegatingSecurityContext( (Object)null, false, ThreadContext.getInetAddress(), session, getSecurityManager() );
        ThreadContext.bind( dummy );

        //now contstruct the 'real' security context to use during the request's thread:
        SecurityContext securityContext = null;
        try {
            securityContext = createSecurityContext( request, response, session );
        } finally {
            //remove the dummy in any case
            ThreadContext.unbindSecurityContext();
        }
        if ( securityContext != null ) {
            ThreadContext.bind( securityContext );
        }

        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        SecurityContext securityContext = getSecurityContext( request, response );

        if ( securityContext != null ) {
            //make sure it is valid:
            try {
                securityContext.getAllPrincipals();
            } catch ( InvalidSecurityContextException e ) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "SecurityContext was invalidated during the request - returning quietly (a new " +
                        "one will be created on the next request)." );
                }
                return;
            }

            bindForSubsequentRequests( request, response, securityContext );
        }

        getSessionWebInterceptor().postHandle( request, response );
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response, Exception exception )
        throws Exception {
        getSessionWebInterceptor().afterCompletion( request, response, exception );
        ThreadContext.unbindSecurityContext();
        unbindInetAddressFromThread();
    }

}
