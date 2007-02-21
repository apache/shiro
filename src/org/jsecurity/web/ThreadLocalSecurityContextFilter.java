/*
 * Copyright (C) 2005-2007 Jeremy Haile
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

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Filter that is used to ensure an {@link org.jsecurity.context.SecurityContext} is bound to the
 * thread local on every request, if it exists in the HTTP session.  Also ensures that
 * any {@link SecurityContext} bound to the thread local during a request is stored
 * in the HTTP session when the request is complete.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class ThreadLocalSecurityContextFilter implements Filter {

    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog(getClass());

    private SecurityManager securityManager;


    public SecurityManager getSecurityManager() {
        return securityManager;
    }


    /**
     * Sets the JSecurity <tt>SecurityManager</tt> to be used by this filter.  This method must be called
     * by the user's framework for this filter to be usable.
     * @param securityManager the securityManager that should be used by this filter.
     */
    public void setSecurityManager(SecurityManager securityManager) {
        this.securityManager = securityManager;
    }


    /**
     * Implemented for interface - does nothing.
     */
    public void init(FilterConfig filterConfig) throws ServletException { }


    /**
     * Before the filter continues, any {@link SecurityContext} is bound to the thread local for the
     * duration of the request.  After the filter returns from the request, any thread local
     * {@link SecurityContext} is set back as an attribute on the session.  After every request,
     * the thread local is cleared to ensure that the context is not leaked if this thread is reused for another
     * request.
     *
     * @param servletRequest the servlet request.
     * @param servletResponse the servlet response.
     * @param filterChain the filter chain.
     */
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;

        try {

            SecurityManager securityManager = getSecurityManager();

            if( securityManager == null ) {
                final String message = "SecurityManager must be configured in filter before it can be used.  This could be " +
                    "done by calling setSecurityManager() on the filter object, or by subclassing the filter to " +
                    "retrieve the SecurityManager from the application framework.";
                if (logger.isErrorEnabled()) {
                    logger.error(message);
                }
                throw new IllegalStateException( message );
            }

            // Create a security context by retrieving the user's principals from the session and construcing
            // a security context
            WebUtils.constructAndBindSecurityContextToThread( request, securityManager);

            //if the SecurityContext.getSession is called, we need an IP as well - to do that, we need to bind
            //the IP of the incoming request to the thread to make sure it is available if that happens:
            WebUtils.bindInetAddressToThread( request );

            filterChain.doFilter( servletRequest, servletResponse );

            // Bind the principals from the security context to the session so that a security context can be
            // reconstructed on the next request
            WebUtils.bindPrincipalsToSessionIfNecessary( request );

        } finally {
            WebUtils.unbindSecurityContextFromThread();
            WebUtils.unbindInetAddressFromThread();
        }


    }

    /**
     * Implemented for interface - does nothing.
     */
    public void destroy() {}
}