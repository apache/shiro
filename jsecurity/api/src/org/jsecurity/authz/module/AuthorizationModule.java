/*
 * Copyright (C) 2005 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.authz.module;

import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.AuthorizationContext;


/**
 * An authorization module is asked to vote on whether or not a user is
 * authorized to perform a particular action, typically by an
 * {@link org.jsecurity.authz.Authorizer Authorizer} implementation.
 * Based on the votes from a set of {@link AuthorizationModule}s, the
 * {@link org.jsecurity.authz.Authorizer Authorizer} will decide
 * whether or not to authorize the user to perform the action.
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public interface AuthorizationModule {

    /**
     * Determines whether or not this authorization module supports voting on
     * the given action.  Returning false indicates that this module will not
     * be called to vote on authorizing an AuthorizedAction.
     *
     * @param action the action which this module must decide if it supports.
     * @return true if this module supports the given action, false otherwise.
     */
    boolean supports( AuthorizedAction action );

    /**
     * Called when the authorization module needs to vote on whether or not
     * a particular {@link AuthorizationContext} is authorized to perform an
     * {@link AuthorizedAction}.  This method is only called if this module
     * {@link #supports supports} the specified <tt>action</tt>.
     *
     * @param context the context that is being grant or denied authorization
     * for the given action.
     * @param action the action that the user is requesting to perform.
     * @return a vote indicating whether or not this module grants authorization
     * to the user, or abstains from voting.
     */
    AuthorizationVote isAuthorized( AuthorizationContext context,
                                    AuthorizedAction action );

}

