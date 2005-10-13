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

package org.jsecurity.ri.authz;

import org.jsecurity.authz.AuthorizationContext;


/**
 * <p>Factory used to create the authorization context that is returned from the
 * {@link org.jsecurity.authc.Authenticator}.  The factory allows the
 * {@link org.jsecurity.authz.AuthorizationContext} returned from the authenticator to be wrapped in a different
 * context (for example a dynamic proxy).</p>
 *
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface AuthorizationContextFactory {

    /**
     * Returns an implementation of the AuthorizationContext instance for the
     * given authorization context.  The returned context may or may not be the same instance or
     * concrete class as the given context.
     * @param context the context that is to be used as the source for the final context.
     * @return an authorization context that will be used by the application.
     */
    AuthorizationContext createAuthContext( AuthorizationContext context );

}