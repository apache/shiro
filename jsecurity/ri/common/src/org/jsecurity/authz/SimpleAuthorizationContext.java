/*
 * Copyright (C) 2005 Jeremy Haile
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

package org.jsecurity.authz;

import java.io.Serializable;
import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * A simple implementation of the {@link AuthorizationContext} interface that
 * maintains all authorization context information in instance variables.  This
 * context implementation has no synchronization, so any required synchronization
 * should be handled outside of this class.  This implementation is not dynamic
 * and does not update automatically, so it will only change when a user is
 * authenticated.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SimpleAuthorizationContext implements AuthorizationContext {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The principal for this auth context.
     */
    private Principal principal;

    /**
     * The roles that apply to this authorization context.
     */
    private Set<Serializable> roles;

    /**
     * The permissions that apply to this authorization context.
     */
    private Set<Permission> permissions;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Constructs a new instance of the auth context.
     * @param principal the principal associated with this auth context.
     * @param roles the roles associated with this auth context.
     * @param permissions the permissions associated with this auth context.
     */
    public SimpleAuthorizationContext(Principal principal, Set<Serializable> roles, Set<Permission> permissions) {
        this.principal = principal;
        this.roles = roles;
        this.permissions = permissions;
    }



    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getPrincipal()
     */
    public Principal getPrincipal() {
        return principal;
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasRole(java.io.Serializable)
     */
    public boolean hasRole(Serializable roleIdentifier) {
        return roles.contains( roleIdentifier );
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasRoles(java.util.List<java.io.Serializable>)
     */
    public boolean[] hasRoles(List<Serializable> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];

        for( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( roleIdentifiers.get(i) );
        }

        return hasRoles;
    }


    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasAllRoles(java.util.Collection<java.io.Serializable>)
     */
    public boolean hasAllRoles(Collection<Serializable> roleIdentifiers) {
        for( Serializable roleIdentifier : roleIdentifiers ) {
            if( !hasRole( roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }


    /**
     * @see AuthorizationContext#hasPermission(java.security.Permission)
     */
    public boolean hasPermission(Permission permission) {
        for( Permission perm : permissions ) {
            if( perm.implies( permission ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * @see AuthorizationContext#hasPermissions(java.util.List<java.security.Permission>)
     */
    public boolean[] hasPermissions(List<Permission> permissions) {
        boolean[] hasPermissions = new boolean[permissions.size()];

        for( int i = 0; i < permissions.size(); i++ ) {
            hasPermissions[i] = hasPermission( permissions.get(i) );
        }
        return hasPermissions;
    }


    /**
     * @see AuthorizationContext#hasAllPermissions(java.util.Collection<java.security.Permission>)
     */
    public boolean hasAllPermissions(Collection<Permission> permissions) {
        for( Permission perm : permissions ) {
            if( !hasPermission(perm) ) {
                return false;
            }
        }
        return true;
    }


    /**
     * @see AuthorizationContext#checkPermission(java.security.Permission)
     */
    public void checkPermission(Permission permission) throws AuthorizationException {
        if( !hasPermission( permission ) ) {
            throw new AuthorizationException( "User [" + getPrincipal().getName() + "] does " +
                                              "not have permission [" + permission.toString() + "]" );
        }
    }


    /**
     * @see AuthorizationContext#checkPermissions(java.util.Collection<java.security.Permission>)
     */
    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        for( Permission permission : permissions ) {
            if( !hasPermission( permission ) ) {
               throw new AuthorizationException( "User [" + getPrincipal().getName() + "] does " +
                                                 "not have permission [" + permission.toString() + "]" );
            }
        }
    }

}