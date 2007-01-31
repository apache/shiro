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

package org.jsecurity.authz;

import org.jsecurity.context.SecurityContext;

/**
 * An <tt>Authorizer</tt> performs the actual authorization check to determine if a particular
 * {@link SecurityContext SecurityContext} is permitted to execute a specific
 * {@link AuthorizedAction AuthorizedAction}.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface Authorizer {

    /**
     * Returns whether or not the specified <tt>SecurityContext</tt> is authorized to
     * execute the given <tt>AuthorizedAction</tt>.
     * @param context the <tt>SecurityContext</tt> used to check for action authorization
     * @param action the action to check for authorization
     * @return true if the <tt>context</tt> can execute the specified <tt>action</tt>, false
     *         otherwise.
     */
    boolean isAuthorized( SecurityContext context, AuthorizedAction action );

    /**
     * Checks whether the user with the given {@link SecurityContext}
     * is authorized to perform the given {@link AuthorizedAction}.  If
     * the user is not authorized to perform the action, an
     * {@link AuthorizationException} is thrown, otherwise the method returns quietly.
     *
     * @param context the security context of the user being authorized.
     * @param action the action that the user is requesting authorization for.
     * @throws AuthorizationException if the context is not authorized to perform the action
     */
    void checkAuthorization( SecurityContext context, AuthorizedAction action )
        throws AuthorizationException;

}

