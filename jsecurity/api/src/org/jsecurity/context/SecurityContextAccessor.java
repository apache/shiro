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

package org.jsecurity.context;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.session.Session;

/**
 * <p>Interface to be implemented by implementations of the JSecurity API
 * to retrieve {@link SecurityContext} objects for the current user's context.</p>
 *
 * <p>The actual implementation of this interface used to retrieve the current
 * {@link SecurityContext} is based on the <code>security.context.accessor.class</code> property.</p>
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public interface SecurityContextAccessor {

    /**
     * Returns a {@link org.jsecurity.session.Session} for the current user's context.
     *
     * @return the current session.
     */
    public Session getSession();

    /**
     * Returns an {@link AuthorizationContext} for the current user's context.
     *
     * @return the current authorization context.
     */
    public AuthorizationContext getAuthorizationContext();

    /**
     * {@link Session#stop() Stops} the user's current session (if it exists) and invalidates
     * the current authorization context.
     *
     * <p>This would normally be called when the user logs out.  Any call to {@link #getSession()}
     * or {@link #getAuthorizationContext()} after <code>invalidate</code> is called should
     * return null.
     */
    public void invalidate();
}