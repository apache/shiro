/*
* Copyright (C) 2005-2007 Jeremy Haile
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
package org.jsecurity.authz.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.Permission;

import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * <p>A simple implementation of the {@link AuthorizationInfo} interface that is useful
 * for most realms.  This implementation uses an internal collection of roles and permissions
 * in order to determine the authorization information of a particular user.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
@SuppressWarnings({"JavaDoc", "SimplifiableIfStatement"})
public class SimpleAuthorizationInfo implements AuthorizationInfo {

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
     * The roles that apply to this info object.
     */
    protected Collection<String> roles;

    /**
     * The permissions that apply to this info object.
     */
    protected Collection<Permission> permissions;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    /**
     * Constructs a new instance of the authorization info with multiple principals.
     * @param roles the roles associated with this auth info.
     * @param permissions the permissions associated with this authorization info.
     */
    @SuppressWarnings( "unchecked" )
    public SimpleAuthorizationInfo(Collection<String> roles, Collection<Permission> permissions) {
        if( roles != null ) {
            this.roles = roles;
        } else {
            this.roles = Collections.EMPTY_LIST;
        }

        if( permissions != null ) {
            this.permissions = permissions;
        } else {
            this.permissions = Collections.EMPTY_LIST;
        }
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    public boolean hasRole(String roleIdentifier) {
        if( roles != null ) {
            return roles.contains( roleIdentifier );
        } else {
            return false;
        }

    }


    public boolean[] hasRoles(List<String> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];

        for( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( roleIdentifiers.get(i) );
        }

        return hasRoles;
    }


    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        for( String roleIdentifier : roleIdentifiers ) {
            if( !hasRole( roleIdentifier ) ) {
                return false;
            }
        }
        return true;
    }



    public boolean isPermitted(Permission permission) {

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


    public boolean[] isPermitted(List<Permission> permissions) {
        boolean[] implies = new boolean[permissions.size()];

        for( int i = 0; i < permissions.size(); i++ ) {
            implies[i] = isPermitted( permissions.get(i) );
        }
        return implies;
    }


    public boolean isPermittedAll(Collection<Permission> permissions) {

        if( permissions != null ) {
            for( Permission perm : permissions ) {
                if( !isPermitted(perm) ) {
                    return false;
                }
            }
        }
        return true;
    }


    public void checkPermission(Permission permission) throws AuthorizationException {
        if( !isPermitted( permission ) ) {
            throw new AuthorizationException( "User does not have permission [" + permission.toString() + "]" );
        }
    }


    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                if( !isPermitted( permission ) ) {
                   throw new AuthorizationException( "User does not have permission [" + permission.toString() + "]" );
                }
            }
        }
    }

    public void checkRole(String role) {
        if( !hasRole( role ) ) {
            throw new AuthorizationException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles(Collection<String> roles) {
       if( roles != null ) {
            for( String role : roles ) {
                checkRole( role );
            }
        }
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();

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