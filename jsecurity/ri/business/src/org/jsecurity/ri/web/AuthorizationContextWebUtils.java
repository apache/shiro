/*
 * Copyright (C) 2005 Jeremy Haile
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Utility method class used to consolidate functionality between any filter, interceptor, etc.
 * that is used for binding an {@link AuthorizationContext} to the thread local and
 * HTTP Session.
 *
 * @see AuthorizationContextFilter
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class AuthorizationContextWebUtils {

    /**
     * The key that is used to store the authorization context in the session.
     */
    private static final String AUTH_CONTEXT_SESSION_KEY = AuthorizationContext.class.getName();

    /**
     * Binds any {@link AuthorizationContext} found in the HTTP session to the thread local using the
     * {@link ThreadContext}.
     * @param request the HTTP request.
     */
    public static void bindSessionContextToThreadLocal( HttpServletRequest request ) {

        HttpSession session = request.getSession( false );

        if( session != null ) {

            AuthorizationContext beforeContext =
                (AuthorizationContext) session.getAttribute( AUTH_CONTEXT_SESSION_KEY );

            if( beforeContext != null ) {
                ThreadContext.put( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY, beforeContext );
            }
        }
    }

    /**
     * Binds any {@link AuthorizationContext} found in the thread local to the HTTP session
     * so it will be available to future requests.
     * @param request the HTTP request.
     */
    public static void bindThreadLocalContextToSession( HttpServletRequest request ) {

        HttpSession session = request.getSession();

        AuthorizationContext afterContext =
            (AuthorizationContext) ThreadContext.get( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY );
        if( afterContext != null ) {
            session.setAttribute( AUTH_CONTEXT_SESSION_KEY, afterContext );
        }
    }

    /**
     * Clears the thread local context of the {@link AuthorizationContext} if one is bound.
     */
    public static void clearThreadLocalContext() {
        // Make sure we always clear the thread local before returning
        if( ThreadContext.containsKey( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY ) ) {
            ThreadContext.remove( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY );
        }
    }

}
