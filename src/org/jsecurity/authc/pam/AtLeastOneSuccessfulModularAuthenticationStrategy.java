/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.authc.pam;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authz.SimpleAuthorizingAccount;
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

    public Account beforeAllAttempts( Collection<? extends Realm> realms, AuthenticationToken token ) throws AuthenticationException {
        return new SimpleAuthorizingAccount();
    }

    public Account beforeAttempt( Realm realm, AuthenticationToken token, Account aggregate ) throws AuthenticationException {
        return aggregate;
    }

    public Account afterAttempt( Realm realm, AuthenticationToken token, Account account, Account aggregate, Throwable t )
        throws AuthenticationException {
        if ( account != null ) {
            ((SimpleAuthorizingAccount)aggregate).merge(account);
        }
        return aggregate;
    }

    public Account afterAllAttempts( AuthenticationToken token, Account aggregate ) throws AuthenticationException {
        //we know if one or more were able to succesfully authenticate if the aggregated account object does not
        //contain null or empty data:
        boolean oneOrMoreSuccessful = aggregate != null && (aggregate.getPrincipals() != null );

        if ( !oneOrMoreSuccessful ) {
            throw new AuthenticationException( "Authentication token of type [" + token.getClass() + "] " +
                "could not be authenticated by any configured realms.  Please ensure that at least one realm can " +
                "authenticate these tokens." );
        }

        return aggregate;
    }
}
