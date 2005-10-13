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

package org.jsecurity.ri.context;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.session.Session;
import org.jsecurity.session.SecureSession;
import org.jsecurity.ri.util.ThreadContext;
import org.jsecurity.context.SecurityContextAccessor;

/**
 * Implementation of {@link SecurityContextAccessor} that retrieves security context information
 * from a thread local variable using the {@link ThreadContext} class.
 *
 * @author Jeremy Haile
 * @since 0.1
 */
public class ThreadLocalSecurityContextAccessor implements SecurityContextAccessor {

    /**
     * @see org.jsecurity.context.SecurityContextAccessor#getSession() SecurityContextAccessor.getSession()
     */
    public SecureSession getSession() {
        return (SecureSession) ThreadContext.get( ThreadContext.SESSION_KEY );
    }

    /**
     * @see org.jsecurity.context.SecurityContextAccessor#getAuthorizationContext() SecurityContextAccessor.getAuthorizationContext()
     */
    public AuthorizationContext getAuthorizationContext() {
        return (AuthorizationContext) ThreadContext.get( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
    }


    /**
     * @see org.jsecurity.context.SecurityContextAccessor#invalidate() SecurityContextAccessor.invalidate()
     */
    public void invalidate() {

        // Stop the current session if one exists
        Session session = getSession();
        if( session != null ) {
            getSession().stop();
        }

        ThreadContext.remove( ThreadContext.AUTHORIZATION_CONTEXT_KEY );
    }
}