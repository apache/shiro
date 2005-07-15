package org.jsecurity.authz;

import java.security.Permission;
import java.security.Principal;
import java.util.Set;
import java.io.Serializable;

/**
 *
 * @author Les Hazlewood
 */
public interface AuthorizationContext {

    Principal getPrincipal();

    boolean hasRole( Serializable roleIdentifier );

    boolean hasRoles( Set<Serializable> roleIdentifiers );

    boolean hasPermission( Permission permission );

    boolean hasPermissions( Set<Permission> permissions );

    void checkPermission( Permission permission ) throws AuthorizationException;

    void checkPermissions( Set<Permission> permissions ) throws AuthorizationException;

    Object getValue( Object key );
}
