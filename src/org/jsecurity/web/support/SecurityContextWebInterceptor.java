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
package org.jsecurity.web.support;

import org.jsecurity.context.SecurityContext;
import org.jsecurity.context.support.InvalidSecurityContextException;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.WebInterceptor;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpSession;
import java.util.List;

/**
 * Builds a {@link org.jsecurity.context.SecurityContext SecurityContext} based on a web request and makes it
 * accessible via the {@link ThreadContext}.
 * 
 * <p>Consolidates common behaviors in obtaining a SecurityContext in different
 * web environments (e.g. Servlet Filters, framework specific interceptors, etc).
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class SecurityContextWebInterceptor extends DefaultWebSecurityContextFactory implements WebInterceptor {

    public boolean preHandle( ServletRequest request, ServletResponse response ) throws Exception {
        //useful for a number of JSecurity components - do it in case this interceptor is the only one configured:
        bindInetAddressToThread( request );

        SecurityContext sc = createSecurityContext( request, response );
        //make available during the thread that processes request:
        if ( sc != null ) {
            ThreadContext.bind( sc );
        }
        return true;
    }

    protected void bindForSubsequentRequests( ServletRequest request, ServletResponse response, SecurityContext securityContext ) {
        HttpSession httpSession = toHttp(request).getSession();
        List allPrincipals = securityContext.getAllPrincipals();
        if ( allPrincipals != null && !allPrincipals.isEmpty() ) {
            httpSession.setAttribute( PRINCIPALS_SESSION_KEY, allPrincipals );
        }
        httpSession.setAttribute( AUTHENTICATED_SESSION_KEY, securityContext.isAuthenticated() );
    }

    public void postHandle( ServletRequest request, ServletResponse response )
        throws Exception {
        SecurityContext securityContext = getSecurityContext( request, response );

        if ( securityContext != null ) {
            try {
                bindForSubsequentRequests( request, response, securityContext );
            } catch ( InvalidSecurityContextException e ) {
                HttpSession httpSession = toHttp(request).getSession(false);
                if ( httpSession != null ) {
                    try {
                        httpSession.removeAttribute( PRINCIPALS_SESSION_KEY );
                        httpSession.removeAttribute( AUTHENTICATED_SESSION_KEY );
                    } catch ( Exception e1 ) {
                        if ( log.isTraceEnabled() ) {
                            log.trace( "Unable to successfully clean http session for invalid security context.", e1); 
                        }
                    }
                }
                if ( log.isTraceEnabled() ) {
                    log.trace( "SecurityContext was invalidated during the request - returning quietly (a new " +
                        "one will be created on the next request)." );
                }
            }
        }
    }

    public void afterCompletion( ServletRequest request, ServletResponse response, Exception exception )
        throws Exception {
        ThreadContext.unbindSecurityContext();
        unbindInetAddressFromThread();
    }
}
