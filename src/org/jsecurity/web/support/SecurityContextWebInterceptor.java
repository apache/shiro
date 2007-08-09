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
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.List;

/**
 * Builds a previously initialized {@link org.jsecurity.context.SecurityContext SecurityContext} based on a web request.
 *
 * <p>Primarily a parent class to consolidate common behaviors in obtaining a SecurityContext in different
 * web environments (e.g. Servlet Filters, framework specific interceptors, etc).
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SecurityContextWebInterceptor extends SecurityWebInterceptor {

    protected enum SecurityContextStorageOrder {
        Cookie_HttpSession_JSecuritySession,
        Cookie_JSecuritySession_HttpSession
    }

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

    /**
     * If a cookie is not used to store the Principal object(s) that will be used to re-construct a SecurityContext
     * on every request, a <tt>false</tt> value here (default) will attempt to use the JSecurity Session to
     * store the Principal(s) between requests, if it exists.  If it does not exist, then the storage mechanism will
     * always fall back to the HttpSession.
     *
     * <p>If a cookie is not used to store the Principal(s), and this value is <tt>true</tt>, the JSecurity Session
     * is not utilized at all - instead the HttpSession will be used immediately to store the Principal(s).
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
    }

    protected List<Principal> getPrincipalsFromCookie( HttpServletRequest request ) {
        return null;//no cookie storage by default - application Principals are application dependent and require the 
        //app to do string-to-principal conversion & vice versa for cookies to work;
    }

    @SuppressWarnings( "unchecked" )
    protected List<Principal> getPrincipalsFromJSecuritySession( HttpServletRequest request ) {

        //request object is ignored, JSecurity default is to get the JSecurity Session from the thread.  This means
        //a JSecurity Session interception mechanism of some sort (filter, interceptor, etc) must be configured before 
        //this object.

        List<Principal> principals = null;
        Session session = ThreadContext.getSession();
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
                log.trace( "JSecurity Session does not exist.  Ignoring as a resource to attempt to construct a " +
                    "SecurityContext instance." );
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

    protected boolean isAuthenticatedFromJSecuritySession( HttpServletRequest request ) {

        // Defaults to false unless found in the session
        boolean authenticated = false;
        Session session = ThreadContext.getSession();
        if ( session != null ) {
            Boolean boolAuthenticated = (Boolean)session.getAttribute( AUTHENTICATED_SESSION_KEY );
            if( boolAuthenticated != null ) {
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
            if( boolAuthenticated != null ) {
                authenticated = boolAuthenticated;
            }
        }
        return authenticated;
    }

    @SuppressWarnings( "unchecked" )
    protected List<Principal> getPrincipals( ServletRequest servletRequest ) {

        HttpServletRequest request = (HttpServletRequest)servletRequest;

        List<Principal> principals = getPrincipalsFromCookie( request );

        if ( principals == null || principals.isEmpty() ) {

            if ( !isPreferHttpSessionStorage() ) {
                principals = getPrincipalsFromJSecuritySession( request );
            }

            if ( principals == null || principals.isEmpty() ) {
                //fall back to HttpSession:
                principals = getPrincipalsFromHttpSession( request );
            }
        }

        return principals;
    }

    protected boolean isAuthenticated( ServletRequest servletRequest ) {

        HttpServletRequest request = (HttpServletRequest)servletRequest;

        boolean authenticated;

        if( !isPreferHttpSessionStorage() ) {
            authenticated = isAuthenticatedFromJSecuritySession( request );
        } else {
            //fall back to HttpSession:
            authenticated = isAuthenticatedFromHttpSession( request );
        }

        return authenticated;
    }

    protected SecurityContext buildSecurityContext( List<Principal> principals, boolean authenticated, SecurityManager securityManager ) {
        return new DelegatingSecurityContext( principals, authenticated, securityManager);
    }

    protected SecurityContext buildSecurityContext( ServletRequest request,
                                                    ServletResponse response,
                                                    List<Principal> principals,
                                                    boolean authenticated ) {

        SecurityContext securityContext;

        if ( securityManager == null ) {
            final String message = "the SecurityManager attribute must be configured.  This could be " +
                "done by calling setSecurityManager() on the " + getClass() + " instance, or by subclassing this " +
                "class to retrieve the SecurityManager from an application framework.";
            if ( log.isErrorEnabled() ) {
                log.error( message );
            }
            throw new IllegalStateException( message );
        }
        securityContext = buildSecurityContext( principals, authenticated, securityManager );

        return securityContext;
    }


    public SecurityContext buildSecurityContext( ServletRequest request, ServletResponse response ) {
        List<Principal> principals = getPrincipals( request );
        boolean authenticated = isAuthenticated( request );
        return buildSecurityContext( request, response, principals, authenticated );
    }

    protected void bindToThread( SecurityContext securityContext ) {
        ThreadContext.bind( securityContext );
    }

    protected void unbindSecurityContextFromThread() {
        ThreadContext.unbindSecurityContext();
    }

    protected boolean bindInCookieForSubsequentRequests( HttpServletRequest request, HttpServletResponse response,
                                                         SecurityContext securityContxt ) {
        //todo This looks wrong.  Does it need to be fixed before 0.2?
        return false;
    }

    protected boolean bindInJSecuritySessionForSubsequentRequests( HttpServletRequest request, HttpServletResponse response,
                                                                   SecurityContext securityContext ) {
        boolean saved = false;

        Session session;

        try {
            session = securityContext.getSession();
        } catch ( Exception t ) {
            if ( log.isWarnEnabled() ) {
                String msg = "Unable to acquire a JSecurity Session from the SecurityContext.  SecurityContext " +
                    "Principal(s) cannot be stored here for access on subsequent requests: ";
                log.warn( msg, t );
            }
            return false;
        }

        try {
            if ( session != null ) {
                // don't overwrite any previous credentials - i.e. SecurityContext swapping for a previously
                // initialized session is not allowed.
                if ( session.getAttribute( PRINCIPALS_SESSION_KEY ) == null ) {
                    session.setAttribute( PRINCIPALS_SESSION_KEY, securityContext.getAllPrincipals() );
                }
                Boolean currentAuthenticated = (Boolean) session.getAttribute( AUTHENTICATED_SESSION_KEY );
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
        if ( httpSession.getAttribute( PRINCIPALS_SESSION_KEY ) == null ) {
            httpSession.setAttribute( PRINCIPALS_SESSION_KEY, securityContext.getAllPrincipals() );
        }
        Boolean currentAuthenticated = (Boolean) httpSession.getAttribute( AUTHENTICATED_SESSION_KEY );
        if ( currentAuthenticated == null || !currentAuthenticated.equals( securityContext.isAuthenticated() ) ) {
            httpSession.setAttribute( AUTHENTICATED_SESSION_KEY, securityContext.getAllPrincipals() );
        }
        return true;
    }

    protected void bindForSubsequentRequests( HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext ) {
        if ( securityContext != null ) {
            boolean saved = bindInCookieForSubsequentRequests( request, response, securityContext );
            if ( !saved ) {
                if ( !isPreferHttpSessionStorage() ) {
                    saved = bindInJSecuritySessionForSubsequentRequests( request, response, securityContext );
                }
            }
            if ( !saved ) {
                //fall back to HttpSession:
                saved = bindInHttpSessionForSubsequentRequests( request, response, securityContext );
            }
        }
    }

    public boolean preHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        SecurityContext securityContext = buildSecurityContext( request, response );
        if ( securityContext != null ) {
            bindToThread( securityContext );
        }
        //useful for a number of JSecurity components - do it in case this interceptor is the only one configured:
        bindInetAddressToThread( request );
        return true;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        SecurityContext securityContext = ThreadContext.getSecurityContext();
        if ( securityContext != null ) {
            bindForSubsequentRequests( request, response, securityContext );
        }
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response, Exception exception )
        throws Exception {
        unbindSecurityContextFromThread();
        unbindInetAddressFromThread();
    }

}
