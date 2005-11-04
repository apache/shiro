package org.jsecurity.ri.authz.support;

import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.authz.DelegatingAuthorizationContext;
import org.jsecurity.ri.authz.Realm;

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
        return new DelegatingAuthorizationContext( info.getPrincipal(), this.realm );
    }
}
