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
public class SecurityContextWebSupport extends SecurityWebSupport {

    protected enum SecurityContextStorageOrder { Cookie_HttpSession_JSecuritySession,
                                                 Cookie_JSecuritySession_HttpSession }

    /**
     * The key that is used to store subject principals in the session.
     */
    public static final String PRINCIPALS_SESSION_KEY =
        SecurityContextWebSupport.class.getName() + "_PRINCIPALS_SESSION_KEY";

    protected SecurityManager securityManager = null;

    protected SecurityContextStorageOrder storageOrder = SecurityContextStorageOrder.Cookie_JSecuritySession_HttpSession;

    public SecurityContextWebSupport(){}

    public SecurityManager getSecurityManager() {
        return securityManager;
    }

    public void setSecurityManager( SecurityManager securityManager ) {
        this.securityManager = securityManager;
    }

    public SecurityContextStorageOrder getStorageOrder() {
        return storageOrder;
    }

    public void setStorageOrder( SecurityContextStorageOrder storageOrder ) {
        this.storageOrder = storageOrder;
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
        if( httpSession != null ) {
            principals =  (List<Principal>) httpSession.getAttribute( PRINCIPALS_SESSION_KEY );
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
    protected List<Principal> getPrincipals( ServletRequest servletRequest ) {

        HttpServletRequest request = (HttpServletRequest)servletRequest;

        List<Principal> principals = getPrincipalsFromCookie( request );

        if ( principals == null || principals.isEmpty() ) {
            if ( getStorageOrder().equals( SecurityContextStorageOrder.Cookie_JSecuritySession_HttpSession ) ) {
                principals = getPrincipalsFromJSecuritySession( request );
            }
            if ( principals == null || principals.isEmpty() ) { //fall back to http session
                principals = getPrincipalsFromHttpSession( request );
            }
        }
        
        return principals;
    }

    protected SecurityContext buildSecurityContext( List<Principal> principals, SecurityManager securityManager ) {
        return new DelegatingSecurityContext( principals, securityManager );
    }

    protected SecurityContext buildSecurityContext( ServletRequest servletRequest, ServletResponse servleResponse,
                                                    List<Principal> principals ) {

        SecurityContext securityContext = null;

        if( principals != null && !principals.isEmpty() ) {
            SecurityManager securityManager = getSecurityManager();
            if ( securityManager == null ) {
                final String message = "the SecurityManager attribute must be configured.  This could be " +
                    "done by calling setSecurityManager() on the " + getClass() + " instance, or by subclassing this " +
                    "class to retrieve the SecurityManager from an application framework.";
                if (log.isErrorEnabled()) {
                    log.error(message);
                }
                throw new IllegalStateException( message );
            }
            securityContext = buildSecurityContext( principals, securityManager );
        }

        return securityContext;
    }


    public SecurityContext buildSecurityContext( ServletRequest request, ServletResponse response ) {
        List<Principal> principals = getPrincipals( request );
        return buildSecurityContext( request, response, principals );
    }

    protected void bindToThread( SecurityContext securityContext ) {
        ThreadContext.bind( securityContext );
    }

    protected void unbindSecurityContextFromThread() {
        ThreadContext.unbindSecurityContext();
    }

    protected void bindForSubsequentRequests( HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext ) {
        if ( securityContext != null ) {
            Session session = securityContext.getSession( false );
            if( session != null && session.getAttribute( PRINCIPALS_SESSION_KEY) == null ) {
                session.setAttribute( PRINCIPALS_SESSION_KEY, securityContext.getAllPrincipals() );

            } else {
                HttpSession httpSession = request.getSession();
                if( httpSession.getAttribute( PRINCIPALS_SESSION_KEY ) == null ) {
                    httpSession.setAttribute( PRINCIPALS_SESSION_KEY, securityContext.getAllPrincipals() );
                }
            }
        }
    }

}
