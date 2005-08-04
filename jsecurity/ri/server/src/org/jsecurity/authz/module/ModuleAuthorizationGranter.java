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
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizationGranter;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;


/**
 * An implementation of {@link org.jsecurity.authz.AuthorizationGranter} that
 * grants authorization based on a set of authorization votes from a set of
 * {@link AuthorizationModule}s.
 *
 * todo Currently uses delegation, should we instead make this abstract and make specific subclasses that implement isAuthorized()?
 *
 * @author Jeremy Haile
 */
public class ModuleAuthorizationGranter implements AuthorizationGranter {

    /*------------------------------------
     *         C O N S T A N T S         |
     *================================== */

    /*------------------------------------
     *          I N S T A N C E          |
     *================================== */
    /**
     * The authorization module strategy used to determine whether a user should
     * be granted authorization based on votes returned from the set of
     * authorization modules.
     */
    protected ModuleAuthorizationStrategy strategy;

    /**
     * The set of authorization modules that are consulted for authorization
     * requests made to this module.
     */
    protected Set<AuthorizationModule> authorizationModules;


    /*------------------------------------
     *       C O N S T R U C T O R S     |
     *================================== */
    /**
     * Initializes this instance with no authorization modules and the default
     * {@link NoDenialStrategy} authorization strategy.
     */
    public ModuleAuthorizationGranter() {
        this.authorizationModules = new HashSet<AuthorizationModule>();
        this.strategy = new NoDenialStrategy();
    }


    /*------------------------------------
     *   A C C E S S / M O D I F I E R   |
     *================================== */
    public void setAuthorizationModules( Set<AuthorizationModule> authorizationModules ) {
        this.authorizationModules = authorizationModules;
    }


    /*------------------------------------
     *           M E T H O D S           |
     *================================== */
    /**
     * Checks whether the given context is authorized to perform the given action
     * by asking each of the authorization modules to vote on whether or not
     * to grant authorization.
     * @param context the context of the user being authorized.
     * @param action the action the user is requesting authorization for.
     */
    public void checkAuthorization( AuthorizationContext context,
                                    AuthorizationAction action ) {

        Map<AuthorizationModule, AuthorizationVote> votes =
                new HashMap<AuthorizationModule,AuthorizationVote>( authorizationModules.size() );

        // Gather the authorization votes from each module
        for( AuthorizationModule module : authorizationModules ) {

            // Only collect a vote if the module supports voting on the particular
            // action
            if( module.supports( action ) ) {
                AuthorizationVote vote = module.isAuthorized( context, action );
                votes.put( module, vote );
            }

        }

        // Use the strategy to determine whether or not
        if( strategy.isAuthorized( context, action, votes ) == false ) {
            throw new AuthorizationException( "Authorization to perform action [" + action + "] " +
                                              "failed.");
        }
    }
}

