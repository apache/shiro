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

package org.jsecurity.ri.authz;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationContext;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.NoSuchPrincipalException;

import java.security.Permission;
import java.security.Principal;
import java.util.*;

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
     * Commons-logger.
     */
    protected transient final Log logger = LogFactory.getLog( getClass() );

    /**
     * The principals that represent the identity of the user
     * for this authorization context.
     */
    protected List<Principal> principals;

    /**
     * The roles that apply to this authorization context.
     */
    protected Collection<String> roles;

    /**
     * The permissions that apply to this authorization context.
     */
    protected Collection<Permission> permissions;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Constructs a new instance of the authorization context with a single principal.
     * @param principal the principal associated with this auth context.
     * @param roles the roles associated with this auth context.
     * @param permissions the permissions associated with this auth context.
     */
    public SimpleAuthorizationContext(Principal principal, Collection<String> roles, Collection<Permission> permissions) {
        this.principals = new ArrayList<Principal>(1);
        this.principals.add( principal );
        this.roles = roles;
        this.permissions = permissions;
    }

    /**
     * Constructs a new instance of the authorization context with multiple principals.
     * @param principals the principals associated with this authorization context.
     * @param roles the roles associated with this auth context.
     * @param permissions the permissions associated with this authorization context.
     */
    public SimpleAuthorizationContext(List<Principal> principals, Collection<String> roles, Collection<Permission> permissions) {
        this.principals = principals;
        this.roles = roles;
        this.permissions = permissions;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * If multiple principals are defined, this method will return the first
     * principal in the list of principals.
     * @see org.jsecurity.authz.AuthorizationContext#getPrincipal()
     */
    public Principal getPrincipal() throws NoSuchPrincipalException {
        if( principals.size() < 1 ) {
            throw new NoSuchPrincipalException( "No principals are associated with this authorization context." );
        }
        return this.principals.get(0);
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getAllPrincipals()
     */
    public Collection<Principal> getAllPrincipals() {
        return principals;
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getPrincipalByType(Class) ()
     */
    public Principal getPrincipalByType(Class principalType) throws NoSuchPrincipalException {
        for( Principal principal : principals ) {
            if( principalType.isAssignableFrom( principal.getClass() ) ) {
                return principal;
            }
        }

        throw new NoSuchPrincipalException( "No principal of type [" + principalType + "] is " +
                "associated with this authorization context." );
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#getAllPrincipalsByType(Class)()
     */
    public Collection<Principal> getAllPrincipalsByType(Class principalType) {
        Set<Principal> principalsOfType = new HashSet<Principal>();

        for( Principal principal : principals ) {
            if( principalType.isAssignableFrom( principal.getClass() ) ) {
                principalsOfType.add( principal );
            }
        }
        return principalsOfType;
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasRole(String)
     */
    public boolean hasRole(String roleIdentifier) {
        return roles.contains( roleIdentifier );
    }

    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasRoles(java.util.List<java.io.Serializable>)
     */
    public boolean[] hasRoles(List<String> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];

        for( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( roleIdentifiers.get(i) );
        }

        return hasRoles;
    }


    /**
     * @see org.jsecurity.authz.AuthorizationContext#hasAllRoles(java.util.Collection<java.io.Serializable>)
     */
    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        for( String roleIdentifier : roleIdentifiers ) {
            if( !hasRole( roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }


    /**
     * @see AuthorizationContext#implies(java.security.Permission)
     */
    public boolean implies(Permission permission) {

        if( permissions != null ) {
            for( Permission perm : permissions ) {
                if( perm.implies( permission ) ) {
                    return true;
                }
            }
        }

        if( logger.isDebugEnabled() ) {
            logger.debug( "Context does not imply permission [" + permission + "]" );

            if( permissions == null ) {
                logger.debug( "No permissions are associated with this context.  Permissions are null." );
            } else {
                logger.debug( "Implies permissions:" );
                for( Permission perm : permissions ) {
                    logger.debug( "\t" + perm );
                }
            }
        }

        return false;
    }

    /**
     * @see AuthorizationContext#implies(java.util.List<java.security.Permission>)
     */
    public boolean[] implies(List<Permission> permissions) {
        boolean[] implies = new boolean[permissions.size()];

        for( int i = 0; i < permissions.size(); i++ ) {
            implies[i] = implies( permissions.get(i) );
        }
        return implies;
    }


    /**
     * @see AuthorizationContext#impliesAll(java.util.Collection<java.security.Permission>)
     */
    public boolean impliesAll(Collection<Permission> permissions) {

        if( permissions != null ) {
            for( Permission perm : permissions ) {
                if( !implies(perm) ) {
                    return false;
                }
            }
        }
        return true;
    }


    /**
     * @see AuthorizationContext#checkPermission(java.security.Permission)
     */
    public void checkPermission(Permission permission) throws AuthorizationException {
        if( !implies( permission ) ) {
            throw new AuthorizationException( "User [" + getPrincipal().getName() + "] does " +
                                              "not have permission [" + permission.toString() + "]" );
        }
    }


    /**
     * @see AuthorizationContext#checkPermissions(java.util.Collection<java.security.Permission>)
     */
    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {

        if( permissions != null ) {
            for( Permission permission : permissions ) {
                if( !implies( permission ) ) {
                   throw new AuthorizationException( "User [" + getPrincipal().getName() + "] does " +
                                                     "not have permission [" + permission.toString() + "]" );
                }
            }
        }
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append( "Principals [" ).append( getAllPrincipals() ).append( "] " );

        sb.append( "Roles [" );
        if( roles != null ) {
            for( String role : roles ) {
                sb.append( role ).append( " " );
            }
        }
        sb.append( "] " );

        sb.append( "Permissions [" );
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                sb.append( permission ).append( " " );
            }
        }
        sb.append( "] " );

        return sb.toString();
    }

}