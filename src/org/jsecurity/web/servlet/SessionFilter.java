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
package org.jsecurity.web.servlet;

import org.jsecurity.session.Session;
import org.jsecurity.web.support.DefaultSessionWebInterceptor;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class SessionFilter extends DefaultSessionWebInterceptor implements Filter {

    /**
     * Implemented for interface - does nothing.
     */
    public void init( FilterConfig filterConfig ) throws ServletException {
    }

    /**
     * @param servletRequest  the servlet request.
     * @param servletResponse the servlet response.
     * @param filterChain     the filter chain.
     */
    public void doFilter( ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain )
        throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        Session session = null;
        Exception exception = null;

        try {

            session = preHandle( request, response );

            filterChain.doFilter( servletRequest, servletResponse );

            postHandle( request, response, session );

        } catch ( Exception e ) {
            exception = e;
        } finally {
            try {
                afterCompletion( request, response, session, exception );
            } catch ( Exception e ) {
                String message = "afterCompletion method threw exception: ";
                //noinspection ThrowFromFinallyBlock
                throw new ServletException( message, e );
            }
        }

    }

    /**
     * Implemented for interface - does nothing.
     */
    public void destroy() {
    }

}
