package org.jsecurity.authc.support;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UnknownAccountException;
import org.jsecurity.realm.Realm;

/**
 * <tt>ModularAuthenticationStrategy</tt> implementation that requires <em>all</em> configured realms to
 * <b>successfully</b> process the submitted <tt>AuthenticationToken</tt> during the log-in attempt.
 *
 * <p>If one or more realms do not support the submitted token, or one or more are unable to acquire
 * <tt>AuthenticationInfo</tt> for the token, this implementation will immediately fail the log-in attempt for the
 * associated subject (user).
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class AllSuccessfulModularAuthenticationStrategy implements ModularAuthenticationStrategy {


    public void beforeAttempt( Realm realm, AuthenticationToken token ) throws AuthenticationException {
        Class tokenClass = token.getClass();
        if ( !realm.supports( tokenClass ) ) {
            String msg = "Realm [" + realm + "] of type [" + realm.getClass().getName() + "] does not support " +
                "AuthenticationTokens of type [" + tokenClass.getName() + "].  The [" + getClass().getName() +
                "] implementation requires all configured realm(s) to support and be able to process the submitted " +
                "AuthenticationToken.";
            throw new UnsupportedTokenException( msg );
        }
    }

    public void afterAttempt( Realm realm, AuthenticationToken token, AuthenticationInfo info, Throwable t )
        throws AuthenticationException {
        if( t != null ) {
            if ( t instanceof AuthenticationException ) {
                //propagate:
                throw ((AuthenticationException)t);
            } else {
                String msg = "Unable to acquire authentication info from realm [" + realm + "].  The [" + 
                    getClass().getName() + " implementation requires all configured realm(s) to operate successfully " +
                    "for a successful authentication.";
                throw new AuthenticationException( msg, t );
            }
        }
        if ( info == null ) {
            String msg = "Realm [" + realm + "] could not find any associated account information for the submitted " +
                "AuthenticationToken [" + token + "].  The [" + getClass().getName() + "] implementation requires " +
                "all configured realm(s) to acquire valid authentication info for a submitted token during the " +
                "log-in process.";
            throw new UnknownAccountException( msg );
        }
    }

    public void afterAllAttempts( AuthenticationToken token, AuthenticationInfo aggregated )
        throws AuthenticationException {
        //if the authentication process made it this far (because of the potential exceptions that could have been
        //thrown from the other two methods in this class), then the authentication attempt was successful across all
        //configured realms, so do nothing - allow to continue
    }
}
