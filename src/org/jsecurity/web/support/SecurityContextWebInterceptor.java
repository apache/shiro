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

import org.jsecurity.JSecurityException;
import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.context.support.InvalidSecurityContextException;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebInterceptor;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.net.InetAddress;
import java.security.Principal;
import java.util.List;

/**
 * Builds a previously initialized {@link org.jsecurity.context.SecurityContext SecurityContext} based on a web request.
 * <p/>
 * <p>Primarily a parent class to consolidate common behaviors in obtaining a SecurityContext in different
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

    protected WebSessionFactory webSessionFactory = null;

    /**
     * Determines whether or not to use the HttpSession as the storage mechanism for principals or the JSecurity
     * Session.  The default is <tt>false</tt>, since JSecurity sessions can be accessed across multiple client
     * mediums (more flexible) and HttpSessions cannot.
     */
    protected boolean preferHttpSessionStorage = false;

    public SecurityContextWebInterceptor() {
    }

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager( SecurityManager securityManager ) {
        this.securityManager = securityManager;
    }

    public WebSessionFactory getWebSessionFactory() {
        return webSessionFactory;
    }

    public void setWebSessionFactory( WebSessionFactory webSessionFactory ) {
        this.webSessionFactory = webSessionFactory;
    }

    public boolean isPreferHttpSessionStorage() {
        return preferHttpSessionStorage;
    }

    public void setPreferHttpSessionStorage( boolean preferHttpSessionStorage ) {
        this.preferHttpSessionStorage = preferHttpSessionStorage;
    }

    public void init() {
        SecurityManager securityManager = getSecurityManager();
        if ( securityManager == null ) {
            String msg = "SecurityManager property must be set.";
            throw new IllegalStateException( msg );
        }
        if ( getWebSessionFactory() == null ) {
            DefaultWebSessionFactory factory = new DefaultWebSessionFactory();
            factory.setSessionFactory( securityManager );
            factory.init();
            setWebSessionFactory( factory );
        }
    }

    @SuppressWarnings( "unchecked" )
    protected List<Principal> getPrincipalsFromJSecuritySession( HttpServletRequest request, HttpServletResponse response ) {
        List<Principal> principals = null;
        Session session = getWebSessionFactory().getSession( request, response );
        if ( session != null ) {
            principals = (List<Principal>)session.getAttribute( PRINCIPALS_SESSION_KEY );
            if ( principals == null ) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "JSecurity Session exists, but does not contain any principals from which a " +
                        "SecurityContext may be built.  Returning null and moving on..." );
                }
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No JSecurity Session associated with the request.  Ignoring as a resource to " +
                    "construct a SecurityContext instance." );
            }
        }
        return principals;
    }

    @SuppressWarnings( "unchecked" )
    protected List<Principal> getPrincipalsFromHttpSession( HttpServletRequest request ) {
        List<Principal> principals = null;
        HttpSession httpSession = request.getSession( false );
        if ( httpSession != null ) {
            principals = (List<Principal>)httpSession.getAttribute( PRINCIPALS_SESSION_KEY );
            if ( principals == null ) {
                if ( log.isTraceEnabled() ) {
                    log.trace( "HttpSession exists, but does not contain any principals from which a " +
                        "SecurityContext may be built.  Returning null and moving on..." );
                }
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "HttpSession does not exist.  Ignoring as a resource to attempt to construct a " +
                    "SecurityContext instance." );
            }
        }
        return principals;
    }

    @SuppressWarnings( "unchecked" )
    protected List<Principal> getPrincipals( ServletRequest servletRequest, ServletResponse servletResponse ) {

        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        List<Principal> principals = null;

        if ( !isPreferHttpSessionStorage() ) {
            principals = getPrincipalsFromJSecuritySession( request, response );
        }

        if ( principals == null || principals.isEmpty() ) {
            //fall back to HttpSession:
            principals = getPrincipalsFromHttpSession( request );
        }

        return principals;
    }

    protected boolean isAuthenticatedFromJSecuritySession( HttpServletRequest request, HttpServletResponse response ) {

        // Defaults to false unless found in the session
        boolean authenticated = false;
        Session session = getWebSessionFactory().getSession( request, response );
        if ( session != null ) {
            Boolean boolAuthenticated = (Boolean)session.getAttribute( AUTHENTICATED_SESSION_KEY );
            if ( boolAuthenticated != null ) {
                authenticated = boolAuthenticated;
            }
        }
        return authenticated;
    }

    protected boolean isAuthenticatedFromHttpSession( HttpServletRequest request ) {

        // Defaults to false unless found in the session
        boolean authenticated = false;
        HttpSession httpSession = request.getSession( false );
        if ( httpSession != null ) {
            Boolean boolAuthenticated = (Boolean)httpSession.getAttribute( AUTHENTICATED_SESSION_KEY );
            if ( boolAuthenticated != null ) {
                authenticated = boolAuthenticated;
            }
        }
        return authenticated;
    }

    protected boolean isAuthenticated( ServletRequest servletRequest, ServletResponse servletResponse ) {

        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        boolean authenticated;

        if ( !isPreferHttpSessionStorage() ) {
            authenticated = isAuthenticatedFromJSecuritySession( request, response );
        } else {
            //fall back to HttpSession:
            authenticated = isAuthenticatedFromHttpSession( request );
        }

        return authenticated;
    }

    protected SecurityContext buildSecurityContext( List<Principal> principals, boolean authenticated,
                                                    InetAddress inetAddress, Session session,
                                                    SecurityManager securityManager ) {
        return new DelegatingSecurityContext( principals, authenticated, inetAddress, session, securityManager );
    }

    protected SecurityContext buildSecurityContext( ServletRequest request,
                                                    ServletResponse response,
                                                    List<Principal> principals,
                                                    boolean authenticated ) {

        SecurityContext securityContext;

        SecurityManager securityManager = getSecurityManager();

        if ( securityManager == null ) {
            final String message = "the SecurityManager attribute must be configured.  This could be " +
                "done by calling setSecurityManager() on the " + getClass().getName() + " instance, or by subclassing " +
                "to retrieve the SecurityManager from an application framework.";
            throw new IllegalStateException( message );
        }

        Session session = getWebSessionFactory().getSession( (HttpServletRequest)request, (HttpServletResponse)response );

        securityContext = buildSecurityContext( principals, authenticated,
            getInetAddress( request ), session, securityManager );

        return securityContext;
    }


    public SecurityContext buildSecurityContext( ServletRequest request, ServletResponse response ) {
        List<Principal> principals = getPrincipals( request, response );
        boolean authenticated = isAuthenticated( request, response );
        return buildSecurityContext( request, response, principals, authenticated );
    }

    protected boolean bindInJSecuritySessionForSubsequentRequests( HttpServletRequest request,
                                                                   HttpServletResponse response,
                                                                   SecurityContext securityContext ) {
        boolean saved = false;

        try {
            Session session = securityContext.getSession();

            if ( session != null ) {
                // Don't overwrite any previous credentials - i.e. SecurityContext swapping for a previously
                // initialized session is not allowed.
                // Only store principals if they exist in the security context
                Object currentPrincipal = session.getAttribute( PRINCIPALS_SESSION_KEY );
                List<Principal> allPrincipals = securityContext.getAllPrincipals();
                if ( currentPrincipal == null && allPrincipals != null && !allPrincipals.isEmpty() ) {
                    session.setAttribute( PRINCIPALS_SESSION_KEY, allPrincipals );
                }

                // Only bind if the current value in the session is null or it doesn't equal the security context value
                Boolean currentAuthenticated = (Boolean)session.getAttribute( AUTHENTICATED_SESSION_KEY );
                if ( currentAuthenticated == null || !currentAuthenticated.equals( securityContext.isAuthenticated() ) ) {
                    session.setAttribute( AUTHENTICATED_SESSION_KEY, securityContext.isAuthenticated() );
                }
                saved = true;
            }
        } catch ( Throwable t ) {
            if ( log.isWarnEnabled() ) {
                String msg = "Unable to store SecurityContext Principal(s) collection in JSecurity Session for " +
                    "reconstruction on subsequent requests: ";
                log.warn( msg, t );
            }
        }

        return saved;
    }

    protected boolean bindInHttpSessionForSubsequentRequests( HttpServletRequest request, HttpServletResponse response,
                                                              SecurityContext securityContext ) {
        HttpSession httpSession = request.getSession();

        // Don't overwrite any previous credentials - i.e. SecurityContext swapping for a previously
        // initialized session is not allowed.
        // Only store principals if they exist in the security context
        Object currentPrincipal = httpSession.getAttribute( PRINCIPALS_SESSION_KEY );
        if ( currentPrincipal == null && !securityContext.getAllPrincipals().isEmpty() ) {
            httpSession.setAttribute( PRINCIPALS_SESSION_KEY, securityContext.getAllPrincipals() );
        }

        // Only bind if the current value in the session is null or it doesn't equal the security context value
        Boolean currentAuthenticated = (Boolean)httpSession.getAttribute( AUTHENTICATED_SESSION_KEY );
        if ( currentAuthenticated == null || !currentAuthenticated.equals( securityContext.isAuthenticated() ) ) {
            httpSession.setAttribute( AUTHENTICATED_SESSION_KEY, securityContext.isAuthenticated() );
        }
        return true;
    }

    protected void bindForSubsequentRequests( HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext ) {
        boolean saved = false;
        if ( !isPreferHttpSessionStorage() ) {
            saved = bindInJSecuritySessionForSubsequentRequests( request, response, securityContext );
        }

        if ( !saved ) {
            //always fall back to HttpSession
            bindInHttpSessionForSubsequentRequests( request, response, securityContext );
        }
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {

        //useful for a number of JSecurity components - do it in case this interceptor is the only one configured:
        bindInetAddressToThread( request );

        SecurityContext securityContext = buildSecurityContext( request, response );
        if ( securityContext != null ) {
            ThreadContext.bind( securityContext );
        }

        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        SecurityContext securityContext = ThreadContext.getSecurityContext();

        if ( securityContext != null ) {
            //make sure it is valid:
            try {
                securityContext.getAllPrincipals();
            } catch ( InvalidSecurityContextException e ) {
                if  ( log.isTraceEnabled() ) {
                    log.trace( "SecurityContext was invalidated during the request - returning quietly (a new " +
                        "one will be created on the next request)." );    
                }
                return;
            }

            bindForSubsequentRequests( request, response, securityContext );

            Session session = null;
            try {
                session = securityContext.getSession( false );
                if ( session != null ) {
                    //TODO this is ugly - think of a way to make it cleaner (add method to WebSessionFactory interface?)
                    WebSessionFactory wsf = getWebSessionFactory();
                    if ( wsf instanceof DefaultWebSessionFactory ) {
                        ( (DefaultWebSessionFactory)wsf ).storeSessionId( session, request, response );
                    }
                }
            } catch ( JSecurityException e ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "Encountered exception while trying to bind JSecurity Session for subsequent requests.  " +
                        "Ignoring and returning (next request will create a new session if necessary).", e );
                }
            }
        }
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response, Exception exception )
        throws Exception {
        ThreadContext.unbindSecurityContext();
        unbindInetAddressFromThread();
    }

}
