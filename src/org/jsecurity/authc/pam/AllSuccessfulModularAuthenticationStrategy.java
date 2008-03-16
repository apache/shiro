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
import org.jsecurity.authc.UnknownAccountException;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.realm.Realm;

import java.util.Collection;

/**
 * <tt>ModularAuthenticationStrategy</tt> implementation that requires <em>all</em> configured realms to
 * <b>successfully</b> process the submitted <tt>AuthenticationToken</tt> during the log-in attempt.
 *
 * <p>If one or more realms do not support the submitted token, or one or more are unable to acquire
 * <tt>Account</tt> for the token, this implementation will immediately fail the log-in attempt for the
 * associated subject (user).
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class AllSuccessfulModularAuthenticationStrategy implements ModularAuthenticationStrategy {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public Account beforeAllAttempts( Collection<? extends Realm> realms, AuthenticationToken token ) throws AuthenticationException {
        return new SimpleAuthorizingAccount();
    }

    public Account beforeAttempt( Realm realm, AuthenticationToken token, Account account ) throws AuthenticationException {
        if ( !realm.supports( token ) ) {
            String msg = "Realm [" + realm + "] of type [" + realm.getClass().getName() + "] does not support " +
                " the submitted AuthenticationToken [" + token + "].  The [" + getClass().getName() +
                "] implementation requires all configured realm(s) to support and be able to process the submitted " +
                "AuthenticationToken.";
            throw new UnsupportedTokenException( msg );
        }

        return account;
    }

    public Account afterAttempt( Realm realm, AuthenticationToken token, Account account, Account aggregate, Throwable t )
        throws AuthenticationException {
        if( t != null ) {
            if ( t instanceof AuthenticationException ) {
                //propagate:
                throw ((AuthenticationException)t);
            } else {
                String msg = "Unable to acquire account data from realm [" + realm + "].  The [" +
                    getClass().getName() + " implementation requires all configured realm(s) to operate successfully " +
                    "for a successful authentication.";
                throw new AuthenticationException( msg, t );
            }
        }
        if ( account == null ) {
            String msg = "Realm [" + realm + "] could not find any associated account data for the submitted " +
                "AuthenticationToken [" + token + "].  The [" + getClass().getName() + "] implementation requires " +
                "all configured realm(s) to acquire valid account data for a submitted token during the " +
                "log-in process.";
            throw new UnknownAccountException( msg );
        }

        // If non-null account is returned, then the realm was able to authenticate the
        // user - so merge the account with any accumulated before:
        if (log.isDebugEnabled()) {
            log.debug("Account successfully authenticated using realm of type [" + realm.getClass().getName() + "]");
        }
        ((SimpleAuthorizingAccount)aggregate).merge(account);

        return aggregate;
    }

    public Account afterAllAttempts( AuthenticationToken token, Account aggregate ) throws AuthenticationException {
        //if the authentication process made it this far (because of the potential exceptions that could have been
        //thrown from the other two methods in this class), then the authentication attempt was successful across all
        //configured realms, so just return the aggregate argument
        return aggregate;
    }
}
