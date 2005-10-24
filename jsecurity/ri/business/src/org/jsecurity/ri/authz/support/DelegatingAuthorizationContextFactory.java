package org.jsecurity.ri.authz.support;

import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.ri.authz.support.AbstractAuthorizationContextFactory;
import org.jsecurity.ri.authz.Realm;
import org.jsecurity.ri.authz.DelegatingAuthorizationContext;

import java.security.Principal;

/**
 * Created on: Oct 24, 2005 4:31:18 PM
 *
 * @author Les Hazlewood
 */
public class DelegatingAuthorizationContextFactory extends AbstractAuthorizationContextFactory {

    private Realm realm = null;

    public DelegatingAuthorizationContextFactory(){}

    public void setRealm( Realm realm ) {
        this.realm = realm;
    }

    public void init() {
        if ( this.realm == null ) {
            String msg = "realm property must be set";
            throw new IllegalStateException( msg );
        }
    }

    protected AuthorizationContext onCreateAuthorizationContext( AuthenticationInfo info ) {
        Principal subjectIdentifier = info.getPrincipal();
        if ( subjectIdentifier == null ) {
            String msg = "context parameter must return a valid principal. A " +
                         DelegatingAuthorizationContext.class.getName() + " must maintain " +
                         "a subject identifyier (principal) to invoke a " +
                         Realm.class.getName() + " implementation.";
            throw new IllegalArgumentException( msg );
        }

        return new DelegatingAuthorizationContext( subjectIdentifier, this.realm );
    }
}
