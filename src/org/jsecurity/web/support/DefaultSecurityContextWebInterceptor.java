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
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityContextWebInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class DefaultSecurityContextWebInterceptor extends SecurityContextWebSupport
    implements SecurityContextWebInterceptor {

    public SecurityContext preHandle( HttpServletRequest request, HttpServletResponse response )
        throws Exception {
        SecurityContext securityContext = buildSecurityContext( request, response );
        if ( securityContext != null ) {
            bindToThread( securityContext );
        }
        //useful for a number of JSecurity components - do it in case this interceptor is the only one configured:
        bindInetAddressToThread( request );
        return securityContext;
    }

    public void postHandle( HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext )
        throws Exception {
        if ( securityContext == null ) {
            //get it from the thread:
            securityContext = ThreadContext.getSecurityContext();
        }
        if ( securityContext != null ) {
            bindForSubsequentRequests( request, response, securityContext );
        }
    }

    public void afterCompletion( HttpServletRequest request, HttpServletResponse response, SecurityContext securityContext, Exception exception )
        throws Exception {
        unbindSecurityContextFromThread();
        unbindInetAddressFromThread();
    }
}
