package org.jsecurity.authc.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.Realm;

/**
 * <tt>ModularAuthenticationStrategy</tt> implementation that requires <em>at least one</em> configured realm to
 * successfully process the submitted <tt>AuthenticationToken</tt> during the log-in attempt.
 *
 * <p>This means any number of configured realms do not have to support the submitted log-in token, or they may
 * be unable to acquire <tt>AuthenticationInfo</tt> for the token, but as long as at least one can do both, this
 * Strategy implementation will allow the log-in process to be successful.
 *
 * @since 0.2
 * @author Les Hazlewood
 */
public class AtLeastOneSuccessfulModularAuthenticationStrategy implements ModularAuthenticationStrategy {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public void beforeAttempt( Realm realm, AuthenticationToken token ) throws AuthenticationException {
        //nothing necessary
    }

    public void afterAttempt( Realm realm, AuthenticationToken token, AuthenticationInfo info, Throwable t ) 
        throws AuthenticationException {
        //nothing necessary
    }

    public void afterAllAttempts( AuthenticationToken token, AuthenticationInfo aggregated ) throws AuthenticationException {
        //we know if one or more were able to succesfully authenticate if the aggregated info object does not
        //contain null or empty data:
        boolean oneOrMoreSuccessful =
            (aggregated.getPrincipal() != null ) ||
            (aggregated.getPrincipals() != null && !aggregated.getPrincipals().isEmpty() );

        if ( !oneOrMoreSuccessful ) {
            throw new AuthenticationException( "Authentication token of type [" + token.getClass() + "] " +
                "could not be authenticated by any configured realms.  Check that the authenticator is configured " +
                "with appropriate realm(s)." );
        }
    }
}
