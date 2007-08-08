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

package org.jsecurity.web.servlet;

import org.jsecurity.web.support.AuthenticationWebInterceptor;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TODO - class JavaDoc
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class AuthenticationFilter extends AuthenticationWebInterceptor implements Filter {

    public static final String EXCLUDED_PATHS_PARAM_NAME = "excludedPaths";
    public static final String EXCLUDED_PATHS_DELIMITER_PARAM_NAME = "delimiters";


    protected void processExcludedPaths( FilterConfig config ) throws Exception {
        String delimiters = config.getInitParameter( EXCLUDED_PATHS_DELIMITER_PARAM_NAME );
        if ( delimiters != null ) {
            setExcludedPathsDelimiters( delimiters );
        }
        String excludedPathsString = config.getInitParameter( EXCLUDED_PATHS_PARAM_NAME );
        if ( excludedPathsString != null ) {
            excludedPathsString = excludedPathsString.trim();
            if ( excludedPathsString.length() > 0 ) {
                setExcludedPaths( excludedPathsString );
            }
        }
    }

    public void init( FilterConfig filterConfig ) throws ServletException {
        try {
            processExcludedPaths( filterConfig );
        } catch ( Exception e ) {
            throw new ServletException( "Unable to set excludedPaths property.", e );
        }
        try {
            init();
        } catch ( Exception e ) {
            throw new ServletException( e );
        }
    }

    public void doFilter( ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain )
        throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        Exception exception = null;

        try {

            boolean allowRequest = preHandle( request, response );

            if ( allowRequest ) {
                filterChain.doFilter( request, response );
            }

            postHandle( request, response );

        } catch ( Exception e ) {
            exception = e;
        } finally {
            try {
                afterCompletion( request, response, exception );
            } catch ( Exception e ) {
                String message = "afterCompletion method threw exception: ";
                //noinspection ThrowFromFinallyBlock
                throw new ServletException( message, e );
            }
        }
    }

    public void destroy() {
    }
}