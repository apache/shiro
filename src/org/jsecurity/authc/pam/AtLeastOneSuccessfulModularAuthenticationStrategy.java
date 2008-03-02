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
package org.jsecurity.authc.pam;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.Realm;

import java.util.Collection;

/**
 * <tt>ModularAuthenticationStrategy</tt> implementation that requires <em>at least one</em> configured realm to
 * successfully process the submitted <tt>AuthenticationToken</tt> during the log-in attempt.
 *
 * <p>This means any number of configured realms do not have to support the submitted log-in token, or they may
 * be unable to acquire <tt>Account</tt> for the token, but as long as at least one can do both, this
 * Strategy implementation will allow the log-in process to be successful.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class AtLeastOneSuccessfulModularAuthenticationStrategy implements ModularAuthenticationStrategy {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public void beforeAllAttempts( Collection<? extends Realm> realms, AuthenticationToken token ) throws AuthenticationException {
        //nothing necessary
    }

    public void beforeAttempt( Realm realm, AuthenticationToken token ) throws AuthenticationException {
        //nothing necessary
    }

    public void afterAttempt( Realm realm, AuthenticationToken token, Account account, Throwable t )
        throws AuthenticationException {
        //nothing necessary
    }

    public void afterAllAttempts( AuthenticationToken token, Account aggregated ) throws AuthenticationException {
        //we know if one or more were able to succesfully authenticate if the aggregated account object does not
        //contain null or empty data:

        boolean oneOrMoreSuccessful = aggregated != null && (aggregated.getPrincipal() != null );

        if ( !oneOrMoreSuccessful ) {
            throw new AuthenticationException( "Authentication token of type [" + token.getClass() + "] " +
                "could not be authenticated by any configured realms.  Please ensure that at least one realm can " +
                "authenticate these tokens." );
        }
    }
}
