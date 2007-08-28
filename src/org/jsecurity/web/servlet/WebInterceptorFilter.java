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

import org.jsecurity.web.WebInterceptor;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A <tt>WebInterceptorFilter</tt> is a Servlet Filter that merely delegates all filter operations to a single internally
 * wrapped {@link org.jsecurity.web.WebInterceptor} instance.  It is a simple utility class to cleanly use a
 * <tt>WebInterceptor</tt> as a servlet filter if so desired - the benefit is that you only have to code one 
 * WebInterceptor class, and you can re-use it in multiple environments such as in a servlet container,
 * in Spring or Pico, JBoss, etc.  This Filter represents the mechanism to use that one WebInterceptor directly in a
 * Servlet environment.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public abstract class WebInterceptorFilter extends OncePerRequestFilter {

    protected WebInterceptor webInterceptor = null;

    public WebInterceptor getWebInterceptor() {
        return this.webInterceptor;
    }

    public void setWebInterceptor( WebInterceptor webInterceptor ) {
        this.webInterceptor = webInterceptor;
    }

    public void init() throws Exception {
        WebInterceptor interceptor = createWebInterceptor();
        if ( interceptor == null ) {
            String msg = "WebInterceptor returned by createWebInterceptor() method returned null.";
            throw new IllegalStateException( msg );
        }
        setWebInterceptor( interceptor );

        onInit();
    }

    /**
     * Provides any other initialization behavior beyond creating/initializing the WebInterceptor instance.
     *
     * <p>If needed, the FilterConfig is available during this call via the {@link #getFilterConfig()} method, and the
     * WebInterceptor instance is available via {@link #getWebInterceptor() }.
     *
     * @throws Exception in the case of an error
     */
    protected void onInit() throws Exception {
    }

    /**
     * If needed, the FilterConfig is available during this call via the {@link #getFilterConfig()} method.
     * @return the WebInterceptor delegate instance to use during the filter execution.
     * @throws Exception if there is an error during interceptor processing, but in any case the interceptor's 
     * afterCompletion method will always be called.
     */
    protected abstract WebInterceptor createWebInterceptor() throws Exception;

    public void doFilterInternal( HttpServletRequest request, HttpServletResponse response, FilterChain chain )
        throws IOException, ServletException {

        Exception exception = null;

        WebInterceptor interceptor = getWebInterceptor();

        try {

            boolean continueChain = interceptor.preHandle( request, response );

            if ( continueChain ) {
                chain.doFilter( request, response );
            }

            interceptor.postHandle( request, response );

        } catch ( Exception e ) {
            exception = e;
        } finally {
            try {
                interceptor.afterCompletion( request, response, exception );
            } catch ( Exception e ) {
                if ( log.isErrorEnabled() ) {
                    log.error( "WebInterceptor [" + interceptor + "] afterCompletion method threw an exception: ", e );
                }
            }
        }
    }
}
