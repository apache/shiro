package org.jsecurity.ri.authz.support;

import org.jsecurity.authc.module.AuthenticationInfo;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.authz.AuthorizationContextFactory;

import java.security.Principal;

/**
 * Created on: Oct 24, 2005 4:35:59 PM
 *
 * @author Les Hazlewood
 */
public abstract class AbstractAuthorizationContextFactory
    implements AuthorizationContextFactory {

    public AbstractAuthorizationContextFactory(){}

    public AuthorizationContext createAuthorizationContext( AuthenticationInfo info ) {
        Principal subjectIdentifier = info.getPrincipal();
        if ( subjectIdentifier == null ) {
            String msg = "AuthenticationInfo parameter must return a non-null principal.";
            throw new IllegalArgumentException( msg );
        }
        return onCreateAuthorizationContext( info );
    }

    protected abstract AuthorizationContext onCreateAuthorizationContext( AuthenticationInfo info );

}
