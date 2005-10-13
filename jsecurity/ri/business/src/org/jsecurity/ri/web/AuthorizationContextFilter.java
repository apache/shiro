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

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Description of class.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class AuthorizationContextFilter implements Filter {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final String AUTH_CONTEXT_SESSION_KEY = AuthorizationContext.class.getName();
    
    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void init(FilterConfig filterConfig) throws ServletException {

    }


    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;

        try {

            // Bind a auth context from the session to the thread local
            bindSessionContextToThreadLocal(request);

            filterChain.doFilter( servletRequest, servletResponse );

            // Bind the auth context from the thread local to the session
            bindThreadLocalContextToSession(request);

        } finally {
            // Make sure we always clear the thread local before returning
            if( ThreadContext.containsKey( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY ) ) {
                ThreadContext.remove( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY );
            }
        }


    }

    private void bindSessionContextToThreadLocal( HttpServletRequest request ) {

        HttpSession session = request.getSession( false );
        if( session != null ) {

            AuthorizationContext beforeContext =
                (AuthorizationContext) session.getAttribute( AUTH_CONTEXT_SESSION_KEY );

            if( beforeContext != null ) {
                ThreadContext.put( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY, beforeContext );
            }
        }
    }

    private void bindThreadLocalContextToSession( HttpServletRequest request ) {

        HttpSession session = request.getSession();

        AuthorizationContext afterContext =
            (AuthorizationContext) ThreadContext.get( ThreadContext.AUTHCONTEXT_THREAD_CONTEXT_KEY );
        if( afterContext != null ) {
            session.setAttribute( AUTH_CONTEXT_SESSION_KEY, afterContext );
        }
    }


    public void destroy() {

    }
}