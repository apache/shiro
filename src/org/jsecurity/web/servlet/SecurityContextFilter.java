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

import org.jsecurity.SecurityManager;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebInterceptor;
import org.jsecurity.web.support.SecurityContextWebInterceptor;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter that is used to ensure a {@link org.jsecurity.context.SecurityContext} is made available to the application
 * on every request.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class SecurityContextFilter extends WebInterceptorFilter {

    protected boolean getBoolean( String paramName, boolean defaultValue ) {
        boolean value = defaultValue;

        String stringValue = getFilterConfig().getInitParameter( paramName );
        if ( stringValue != null ) {
            stringValue = stringValue.trim();
            if ( "".equals( stringValue ) ) {
                if (log.isWarnEnabled() ) {
                    log.warn( "Filter init param [" + paramName + "] does not have a " +
                        "valid value (empty).  Defaulting to " + defaultValue + "." );
                }
            }
            stringValue = stringValue.trim();

            try {
                value = Boolean.valueOf( stringValue );
            } catch ( Exception e ) {
                if ( log.isWarnEnabled() ) {
                    log.warn( "Filter init param [" + paramName + "] with value [" + stringValue + "] is not a valid " +
                        "boolean value (true|false).  Defaulting to " + defaultValue + "." );
                }
            }
        }

        return value;
    }

    public void doFilterInternal( ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain )
        throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest)servletRequest;
        HttpServletResponse response = (HttpServletResponse)servletResponse;

        ServletContext servletContext = getServletContext();

        boolean webSessions = isWebSessions();
        request = new JSecurityHttpServletRequest( request, servletContext, webSessions );
        //the JSecurityHttpServletResponse exists to support URL rewriting for session ids.  This is only needed if
        //using JSecurity sessions (i.e. not simple HttpSession based sessions):
        if ( !webSessions ) {
            response = new JSecurityHttpServletResponse( response, servletContext, (JSecurityHttpServletRequest)request );
        }

        ThreadContext.bind( request );
        ThreadContext.bind( response );

        try {
            super.doFilterInternal( request, response, chain );    //To change body of overridden methods use File | Settings | File Templates.
        } finally {
            ThreadContext.unbindServletRequest();
            ThreadContext.unbindServletResponse();
        }
    }

    /**
     * Default implementation pulls the SecurityContext instance from the ServletContext.  Subclasses can override to
     * retrieve from a different location.
     *
     * @return the application's SecurityManager.
     */
    protected SecurityManager getSecurityManager() {
        ServletContext servletContext = getFilterConfig().getServletContext();
        SecurityManager securityManager = (SecurityManager)servletContext.getAttribute( SecurityManagerLoader.SECURITY_MANAGER_CONTEXT_KEY );
        if ( securityManager == null ) {
            String msg = "no SecurityManager instance bound to the ServletContext under key [" +
            SecurityManagerLoader.SECURITY_MANAGER_CONTEXT_KEY + "].  Please ensure that either the " +
                SecurityManagerListener.class.getName() + " listener or the " +
                SecurityManagerServlet.class.getName() + " servlet are configured in web.xml (easiest), or override the " +
                getClass().getName() + ".getSecurityManager() method to retrieve it from a custom location.";
            throw new IllegalStateException( msg );
        }
        return securityManager;
    }

    protected WebInterceptor createWebInterceptor() throws Exception {
        SecurityContextWebInterceptor interceptor = new SecurityContextWebInterceptor();
        SecurityManager securityManager = getSecurityManager();
        interceptor.setSecurityManager( securityManager );
        interceptor.setWebSessions( isWebSessions() );
        interceptor.init();
        return interceptor;
    }



}