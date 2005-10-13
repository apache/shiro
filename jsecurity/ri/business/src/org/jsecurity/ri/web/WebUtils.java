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

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.util.ThreadContext;
import org.jsecurity.session.Session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Utility method class used to consolidate functionality between any filter, interceptor, etc,
 * that is used for binding a JSecurity components such as
 * {@link Session Session}s and {@link AuthorizationContext AuthorizationContext}s to the
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
    private static final String AUTHORIZATION_CONTEXT_KEY =
        AuthorizationContext.class.getName() + "_HTTP_SESSION_KEY";

    private static final String SESSION_ID_KEY =
        Session.class.getName() + "_ID_HTTP_SESSION_KEY";

    public static final String ATTEMPTED_PAGE_KEY =
        WebUtils.class.getName() + "ATTEMPTED_PAGE_SESSION_KEY";

    private WebUtils(){}

    public static void bindToThread( AuthorizationContext authCtx ) {
        if ( authCtx != null ) {
            ThreadContext.put( ThreadContext.AUTHORIZATION_CONTEXT_KEY, authCtx );
        }
    }

    public static void unbindAuthorizationContextFromThread() {
        ThreadContext.remove( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
    }

    public static void bindToThread( Session s ) {
        if ( s != null ) {
            ThreadContext.put( ThreadContext.SESSION_KEY, s );
        }
    }

    public static void unbindSessionFromThread() {
        ThreadContext.remove( ThreadContext.SESSION_KEY );
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

    public static void bindToHttpSession( AuthorizationContext ctx, HttpServletRequest request ) {
        HttpSession httpSession = request.getSession( false );
        if ( httpSession != null && ctx != null) {
            httpSession.setAttribute( AUTHORIZATION_CONTEXT_KEY, ctx );
        }
    }

    public static void unbindAuthorizationContextFromHttpSession( HttpServletRequest request ) {
        HttpSession httpSession = request.getSession( false );
        if ( httpSession != null ) {
            httpSession.removeAttribute( AUTHORIZATION_CONTEXT_KEY );
        }
    }

    public static void bindAuthorizationContextToThread( HttpServletRequest request ) {
        HttpSession session = request.getSession( false );
        if( session != null ) {
            AuthorizationContext ctx =
                (AuthorizationContext)session.getAttribute( AUTHORIZATION_CONTEXT_KEY );
            bindToThread( ctx );
        }
    }

    public static void bindAuthorizationContextToSession( HttpServletRequest request ) {
        AuthorizationContext ctx =
            (AuthorizationContext) ThreadContext.get( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
        bindToHttpSession( ctx, request );
    }

}
