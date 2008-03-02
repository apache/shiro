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
package org.jsecurity.authz;

import org.jsecurity.authc.SimpleAccount;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * <p>A simple implementation of the {@link AuthorizingAccount} interface that is useful
 * for many realms.  This implementation uses an internal collection of roles and permissions
 * in order to perform authorization checks for a particular user.</p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class SimpleAuthorizingAccount extends SimpleAccount implements AuthorizingAccount {

    protected Collection<SimpleRole> roles = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SimpleAuthorizingAccount(){}

    public SimpleAuthorizingAccount( Object principal, Object credentials ) {
        super( principal, credentials );
    }

    public SimpleAuthorizingAccount( Object principal, Object credentials, Collection<String> roleNames ) {
        this( principal, credentials );
        this.roles = toRoles( roleNames );
    }

    public SimpleAuthorizingAccount( Object principal, Object credentials,
                                     Collection<String> roleNames, Collection<Permission> permissions ) {
        super( principal, credentials );
        this.roles = toRoles( roleNames );
        SimpleRole privatePermRole = toPrivateRole( principal, permissions );
        if ( privatePermRole != null ) {
            if ( this.roles == null ) {
                this.roles = new HashSet<SimpleRole>(1);
            }
            this.roles.add(privatePermRole);
        }
    }

    protected SimpleRole toPrivateRole( Object principal, Collection<Permission> perms ) {
        if ( perms != null && !perms.isEmpty() ) {
            //create a 'private' role to encapsulate these permissions:
            String privateRoleName = getClass().getName() + "_PRIVATE_ROLE_" + principal;
            return new SimpleRole(privateRoleName, perms);
        }
        return null;
    }

    protected Collection<SimpleRole> toRoles( Collection<String> roleNames ) {
        Collection<SimpleRole> roles = null;
        if ( roleNames != null && !roleNames.isEmpty() ) {
            roles = new HashSet<SimpleRole>(roleNames.size());
            for( String roleName : roleNames ) {
                roles.add( new SimpleRole( roleName ) );
            }
        }
        return roles;
    }

    public Collection<SimpleRole> getRoles() {
        return roles;
    }

    public void setRoles( Collection<SimpleRole> roles ) {
        this.roles = roles;
    }

    public Set<Permission> getPermissions() {
        Set<Permission> permissions = new HashSet<Permission>();
        for( SimpleRole role : roles ) {
            permissions.addAll( role.getPermissions() );
        }
        return permissions;
    }

    public Set<String> getRolenames() {
        Set<String> rolenames = new HashSet<String>();
        for( SimpleRole role : roles ) {
            rolenames.add( role.getName() );
        }
        return rolenames;
    }

    public void add( SimpleRole role ) {
        Collection<SimpleRole> roles = getRoles();
        if ( roles == null ) {
            roles = new HashSet<SimpleRole>();
            setRoles( roles );
        }
        roles.add( role );
    }

    public boolean hasRole( String rolename ) {
        Collection<SimpleRole> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for( SimpleRole role : roles ) {
                if ( role.getName().equals( rolename ) ) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isPermitted( Permission permission ) {
        Collection<SimpleRole> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for( SimpleRole role : roles ) {
                if ( role.isPermitted( permission ) ) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        boolean[] result;
        if ( roleIdentifiers != null && !roleIdentifiers.isEmpty() ) {
            int size = roleIdentifiers.size();
            result = new boolean[ size ];
            int i = 0;
            for( String roleName : roleIdentifiers ) {
                result[i++] = hasRole( roleName );
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        if ( roleIdentifiers != null && !roleIdentifiers.isEmpty() ) {
            for( String roleName : roleIdentifiers ) {
                if ( !hasRole(roleName ) ) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        boolean[] result;
        if ( permissions != null && !permissions.isEmpty() ) {
            int size = permissions.size();
            result = new boolean[ size ];
            int i = 0;
            for( Permission p : permissions ) {
                result[i++] = isPermitted(p);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        if ( permissions != null && !permissions.isEmpty() ) {
            for( Permission p : permissions ) {
                if ( !isPermitted(p) ) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        if ( !isPermitted(permission) ) {
            String msg = "User is not permitted [" + permission + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        if ( permissions != null && !permissions.isEmpty() ) {
            for( Permission p : permissions ) {
                checkPermission(p);
            }
        }
    }

    public void checkRole(String role) {
        if ( !hasRole( role ) ) {
            String msg = "User does not have role [" + role + "]";
            throw new UnauthorizedException( msg );
        }
    }

    public void checkRoles(Collection<String> roles) {
        if ( roles != null && !roles.isEmpty() ) {
            for( String roleName : roles ) {
                checkRole( roleName );
            }
        }
    }
}