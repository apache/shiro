package org.jsecurity.ri.authz.support;

import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.ri.authz.SimpleAuthorizationContext;

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;

/**
 * Created on: Oct 24, 2005 4:35:13 PM
 *
 * @author Les Hazlewood
 */
public class SimpleAuthorizationContextFactory extends AbstractAuthorizationContextFactory {

    public SimpleAuthorizationContextFactory(){}

    public AuthorizationContext onCreateAuthorizationContext( AuthenticationInfo info ) {
        Principal subjectIdentity = info.getPrincipal();
        Collection<String> roles = info.getRoles();
        Collection<Permission> perms = info.getPermissions();

        return new SimpleAuthorizationContext( subjectIdentity, roles, perms );
    }

}
