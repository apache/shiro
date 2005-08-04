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

package org.jsecurity.authz.module;

import org.jsecurity.authz.AuthorizationAction;
import org.jsecurity.authz.AuthorizationContext;

import java.util.Collection;
import java.util.Map;


/**
 * Instance of {@link ModuleAuthorizationStrategy} that authorizes the user
 * if and only if:
 * <ol>
 * <li>At least one granted vote is given.</li>
 * <li>No denied votes are given.</li>
 * </ol>
 *
 * @author Jeremy Haile
 */
public class NoDenialStrategy implements ModuleAuthorizationStrategy {


    /**
     * @see ModuleAuthorizationStrategy#isAuthorized(org.jsecurity.authz.AuthorizationContext, org.jsecurity.authz.AuthorizationAction, java.util.Map<org.jsecurity.authz.module.AuthorizationModule,org.jsecurity.authz.module.AuthorizationVote>)
     */
    public boolean isAuthorized( AuthorizationContext context,
                                 AuthorizationAction action,
                                 Map<AuthorizationModule, AuthorizationVote> votes ) {

        // If there are no votes, the user cannot be authorized
        if( votes == null || votes.isEmpty() ) {
            return false;
        }

        Collection<AuthorizationVote> voteValues = votes.values();
        if( voteValues.contains( AuthorizationVote.denied ) ) {
            return false;

        } else if( voteValues.contains( AuthorizationVote.granted ) ) {
            return true;

        } else {
            return false;
        }

    }
}

