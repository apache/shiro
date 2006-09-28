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
package org.jsecurity.ri.web;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.ri.authz.DelegatingSecurityContext;
import org.jsecurity.ri.realm.RealmManager;
import org.jsecurity.ri.util.ThreadContext;
import org.jsecurity.ri.util.ThreadUtils;
import org.jsecurity.ri.context.ThreadLocalSecurityContext;
import org.jsecurity.session.Session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
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

    /**
     * The key that is used to store the authorization context in the session.
     */
    public static final String PRINCIPALS_SESSION_KEY =
        Principal.class.getName() + "_SESSION_KEY";

    public static final String SESSION_ID_KEY =
        Session.class.getName() + "_ID_HTTP_SESSION_KEY";

    public static final String ATTEMPTED_PAGE_KEY =
        WebUtils.class.getName() + "_ATTEMPTED_PAGE_SESSION_KEY";

    /**
     * Key that may be used for a http session attribute or request attribute to alert that a referencing session
     * has expired.
     */
    public static final String EXPIRED_SESSION_KEY =
        WebUtils.class.getName() + "_EXPIRED_SESSION_KEY";


    private WebUtils(){}

    public static void bindToThread( SecurityContext authCtx ) {
        ThreadUtils.bindToThread( authCtx );
    }

    public static void unbindSecurityContextFromThread() {
        ThreadUtils.unbindSecurityContextFromThread();
    }

    public static void bindToThread( Session s ) {
        ThreadUtils.bindToThread( s );
    }

    public static void unbindSessionFromThread() {
        ThreadUtils.unbindSessionFromThread();
    }

    public static void bindToHttpSession( Session s, HttpServletRequest request ) {
        if ( s != null ) {
            HttpSession httpSession = request.getSession();
            httpSession.setAttribute( SESSION_ID_KEY, s.getSessionId() );
        }
    }

    public static void unbindSessionFromHttpSession( HttpServletRequest request ) {
        HttpSession httpSession = request.getSession( false );
        if ( httpSession != null ) {
            httpSession.removeAttribute( SESSION_ID_KEY );
        }
    }

    public static void bindToSession( SecurityContext ctx, HttpServletRequest request ) {
        if ( ctx != null ) {
            Session session = (new ThreadLocalSecurityContext()).getSession();
            if( session != null ) {
                session.setAttribute( PRINCIPALS_SESSION_KEY, ctx.getAllPrincipals() );
            } else {
                HttpSession httpSession = request.getSession();
                httpSession.setAttribute( PRINCIPALS_SESSION_KEY, ctx.getAllPrincipals() );
            }
        }
    }

    public static void unbindSecurityContextFromSession( HttpServletRequest request ) {
        Session session = (new ThreadLocalSecurityContext()).getSession();
        if( session != null ) {
            session.removeAttribute( PRINCIPALS_SESSION_KEY );
        } else {
            HttpSession httpSession = request.getSession( false );
            if ( httpSession != null ) {
                httpSession.removeAttribute( PRINCIPALS_SESSION_KEY );
            }
        }
    }

    public static void bindSecurityContextToThread( HttpServletRequest request, RealmManager realmManager ) {
        List<Principal> principals = getPrincipals( request );

        if( principals != null ) {
            SecurityContext ctx = buildSecurityContext( principals, realmManager);
            if( ctx != null ) {
                bindToThread( ctx );
            }
        }
    }


    private static List<Principal> getPrincipals(HttpServletRequest request) {
        List<Principal> principals = null;

        Session session = (new ThreadLocalSecurityContext()).getSession();
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

    private static SecurityContext buildSecurityContext(List<Principal> principals, RealmManager realmManager ) {
        if( principals != null && !principals.isEmpty() ) {
            return new DelegatingSecurityContext( principals, realmManager );
        } else {
            return null;
        }
    }

    public static void bindSecurityContextToSession( HttpServletRequest request ) {
        SecurityContext ctx =
            (SecurityContext) ThreadContext.get( ThreadContext.SECURITY_CONTEXT_KEY );
        bindToSession( ctx, request );
    }

}
