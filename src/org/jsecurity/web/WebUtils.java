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
package org.jsecurity.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.SecurityManager;
import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.DelegatingSecurityContext;
import org.jsecurity.session.Session;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.util.ThreadUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Principal;
import java.util.List;

/**
 * Utility method class used to consolidate functionality between any filter, interceptor, etc,
 * that is used for binding a JSecurity components such as
 * {@link Session Session}s and {@link org.jsecurity.context.SecurityContext SecurityContext}s to the
 * thread and <tt>HTTPSession</tt>.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public abstract class WebUtils {

    protected static transient final Log log = LogFactory.getLog( WebUtils.class );

    /**
     * The key that is used to store subject principals in the session.
     */
    public static final String PRINCIPALS_SESSION_KEY =
        WebUtils.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /**
     * The key that is used to store the session ID in the session.
     */
    public static final String SESSION_ID_KEY =
        WebUtils.class.getName() + "_SESSION_ID_SESSION_KEY";

    /**
     * The key that is used to store the attempted page in the session.
     */
    public static final String ATTEMPTED_PAGE_KEY =
        WebUtils.class.getName() + "_ATTEMPTED_PAGE_SESSION_KEY";

    /**
     * Key that may be used for a http request or session attribute to alert that a referencing JSecurity Session
     * has expired.
     */
    public static final String EXPIRED_SESSION_KEY =
        WebUtils.class.getName() + "_EXPIRED_SESSION_KEY";


    private WebUtils(){}


    /**
     * Binds the given <tt>SecurityContext</tt> to a thread local.
     * @param secCtx the security context to bind.
     */
    public static void bindToThread( SecurityContext secCtx ) {
        ThreadUtils.bindToThread( secCtx );
    }

    /**
     * Unbinds any <tt>SecurityContext</tt> from the thread local.
     */
    public static void unbindSecurityContextFromThread() {
        ThreadUtils.unbindSecurityContextFromThread();
    }

    /**
     * Binds the given <tt>Session</tt> to a thread local.
     * @param session the session to bind.
     */
    public static void bindToThread( Session session ) {
        ThreadUtils.bindToThread( session );
    }

    /**
     * Unbinds any session from the thread local.
     */
    public static void unbindSessionFromThread() {
        ThreadUtils.unbindSessionFromThread();
    }


    /**
     * Constructs a <tt>SecurityContext</tt> by retrieving the current user's principals from their session and
     * then binds the <tt>SecurityContext</tt> to the thread local.  The <tt>SecurityContext</tt> <b>MUST</b> be
     * unbound from the thread at the end of the request by calling {@link #unbindSecurityContextFromThread()}
     * @param request the request that is used to access the user's principals (from session).
     * @param securityManager the current security manager used to construct the <tt>SecurityContext</tt>.
     */
    public static void constructAndBindSecurityContextToThread( HttpServletRequest request, SecurityManager securityManager ) {
        List<Principal> principals = getPrincipals( request );

        if( principals != null ) {
            SecurityContext ctx = buildSecurityContext( principals, securityManager);
            if( ctx != null ) {
                bindToThread( ctx );
            }
        }
    }


    /**
     * Retrieves the current user's principals from their session.  If JSecurity sessions are enabled,
     * the user's principals are retrieved from the JSecurity session.  Otherwise, the HTTP session is used.  This
     * method is called when building a <tt>SecurityContext</tt> to attach to the current thread on each request.
     * @param request the request that will be used to access the HTTP session if necessary.
     * @return the principals retrieved from the user's session.
     */
    @SuppressWarnings( "unchecked" )
    private static List<Principal> getPrincipals(HttpServletRequest request) {
        List<Principal> principals = null;

        Session session = (Session) ThreadContext.get( ThreadContext.SESSION_KEY );
        if( session != null ) {
            principals = (List<Principal>) session.getAttribute( PRINCIPALS_SESSION_KEY );
        } else {
            HttpSession httpSession = request.getSession( false );
            if( httpSession != null ) {
                principals =  (List<Principal>) httpSession.getAttribute( PRINCIPALS_SESSION_KEY );
            }
        }
        return principals;
    }


    /**
     * Builds a <tt>SecurityContext</tt> given a set of principals and a <tt>SecurityManager</tt>  Called on each
     * request to construct the <tt>SecurityContext</tt> that is bound to a thread local.
     * @param principals the current user's principals.
     * @param securityManager the security manager for this application.
     * @return a newly constructed <tt>SecurityContext</tt>
     */
    private static SecurityContext buildSecurityContext(List<Principal> principals, SecurityManager securityManager ) {
        if( principals != null && !principals.isEmpty() ) {
            return new DelegatingSecurityContext( principals, securityManager );
        } else {
            return null;
        }
    }


    /**
     * Binds the current user's principals to their session.  If JSecurity sessions are used, they will be stored
     * in the JSecurity session. Otherwise they are stored in the HTTP session.  This is called after each request
     * to ensure that the principals are stored in the session.  This allows a <tt>SecurityContext</tt> to be
     * constructed on the next request by {@link #constructAndBindSecurityContextToThread(javax.servlet.http.HttpServletRequest, org.jsecurity.SecurityManager)}
     * @param request the request used to retrieve the HTTP session if necessary.
     */
    public static void bindPrincipalsToSessionIfNecessary( HttpServletRequest request ) {
        SecurityContext ctx = (SecurityContext) ThreadContext.get( ThreadContext.SECURITY_CONTEXT_KEY );

        if ( ctx != null ) {
            Session session = ctx.getSession( false );
            if( session != null && session.getAttribute( PRINCIPALS_SESSION_KEY) == null ) {
                session.setAttribute( PRINCIPALS_SESSION_KEY, ctx.getAllPrincipals() );

            } else {
                HttpSession httpSession = request.getSession();
                if( httpSession.getAttribute( PRINCIPALS_SESSION_KEY ) == null ) {
                    httpSession.setAttribute( PRINCIPALS_SESSION_KEY, ctx.getAllPrincipals() );
                }
            }
        }
    }

    public static InetAddress getInetAddress( HttpServletRequest request ) {
        InetAddress clientAddress = null;
        //get the Host/IP the client is coming from:
        String addrString = request.getRemoteHost();
        try {
            clientAddress = InetAddress.getByName( addrString );
        } catch ( UnknownHostException e ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Unable to acquire InetAddress from HttpServletRequest", e );
            }
        }

        return clientAddress;
    }

    public static void bindInetAddressToThread( HttpServletRequest request ) {
        InetAddress ip = getInetAddress( request );
        if ( ip != null ) {
            ThreadUtils.bindToThread( ip );
        }
    }

    public static void unbindInetAddressFromThread() {
        ThreadUtils.unbindInetAddressFromThread();
    }

}
