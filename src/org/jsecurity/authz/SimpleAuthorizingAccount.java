/*
* Copyright (C) 2005-2008 Jeremy Haile, Les Hazlewood
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

import org.jsecurity.authc.Account;
import org.jsecurity.authc.SimpleAccount;

import java.util.*;

/**
 * <p>A simple implementation of the {@link AuthorizingAccount} interface that is useful
 * for many realms.  This implementation caches an internal collection of roles and permissions
 * in order to perform authorization checks for a particular user.</p>
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.2
 */
public class SimpleAuthorizingAccount extends SimpleAccount implements AuthorizingAccount {

    protected Set<SimpleRole> roles;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SimpleAuthorizingAccount() {
    }

    public SimpleAuthorizingAccount(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public SimpleAuthorizingAccount(Object principal, Object credentials, Set<String> roleNames) {
        super(principal, credentials);
        addRoles(roleNames);
    }

    public SimpleAuthorizingAccount(Object principal, Object credentials,
                                    Set<String> roleNames, Set<Permission> permissions) {
        this(principal, credentials, roleNames);
        //only create a private role if there are permissions:
        if ( permissions != null && !permissions.isEmpty() ) {
            addPrivateRole(principal,permissions);
        }
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    @SuppressWarnings({"unchecked"})
    public void merge(Account otherAccount) {
        super.merge(otherAccount);
        if ( otherAccount instanceof SimpleAuthorizingAccount ) {
            SimpleAuthorizingAccount other = (SimpleAuthorizingAccount)otherAccount;
            Set<SimpleRole> otherRoles = other.getRoles();
            if ( otherRoles != null && !otherRoles.isEmpty() ) {
                for( SimpleRole otherRole : otherRoles ) {
                    merge( otherRole );
                }
            }
        }
    }

    protected void merge( SimpleRole role ) {
        SimpleRole existing = getRole( role.getName() );
        if ( existing != null ) {
            Set<Permission> rolePerms = role.getPermissions();
            if ( rolePerms != null && !rolePerms.isEmpty() ) {
                existing.addAll(rolePerms);
            }
        } else {
            add(role);
        }
    }

    protected void addPrivateRole(Object principal, Collection<Permission> perms) {
        SimpleRole privateRole = createPrivateRole( principal );
        if ( perms != null && !perms.isEmpty() ) {
            privateRole.addAll(perms);
        }
        add(privateRole);
    }

    protected String getPrivateRoleName( Object principal ) {
        return getClass().getName() + "_PRIVATE_ROLE_" + principal;
    }

    protected SimpleRole createPrivateRole( Object principal ) {
        String privateRoleName = getPrivateRoleName(principal);
        return new SimpleRole(privateRoleName);    
    }

    public Set<SimpleRole> getRoles() {
        return roles;
    }

    public void setRoles(Set<SimpleRole> roles) {
        this.roles = roles;
    }

    public SimpleRole getRole( String name ) {
        Collection<SimpleRole> roles = getRoles();
        if ( roles != null && !roles.isEmpty() ) {
            for( SimpleRole role : roles ) {
                if ( role.getName().equals(name) ) {
                    return role;
                }
            }
        }
        return null;
    }

    public Set<Permission> getPermissions() {
        Set<Permission> permissions = new HashSet<Permission>();
        for (SimpleRole role : roles) {
            permissions.addAll(role.getPermissions());
        }
        return permissions;
    }

    public Set<String> getRolenames() {
        Set<String> rolenames = new HashSet<String>();
        for (SimpleRole role : roles) {
            rolenames.add(role.getName());
        }
        return rolenames;
    }

    public void addRole( String roleName ) {
        SimpleRole existing = getRole(roleName);
        if ( existing == null ) {
            SimpleRole role = new SimpleRole(roleName);
            add(role);
        }
    }

    public void add(SimpleRole role) {
        Set<SimpleRole> roles = getRoles();
        if (roles == null) {
            roles = new LinkedHashSet<SimpleRole>();
            setRoles(roles);
        }
        roles.add(role);
    }

    public void addRoles( Set<String> roleNames ) {
        if ( roleNames != null && !roleNames.isEmpty() ) {
            for( String name : roleNames ) {
                addRole( name );
            }
        }
    }

    public void addAll(Collection<SimpleRole> roles) {
        if (roles != null && !roles.isEmpty()) {
            Set<SimpleRole> existingRoles = getRoles();
            if (existingRoles == null) {
                existingRoles = new LinkedHashSet<SimpleRole>(roles.size());
                setRoles(existingRoles);
            }
            existingRoles.addAll(roles);
        }

    }

    public boolean hasRole(String roleName) {
        return getRole(roleName) != null;
    }

    public boolean isPermitted(Permission permission) {
        Collection<SimpleRole> roles = getRoles();
        if (roles != null && !roles.isEmpty()) {
            for (SimpleRole role : roles) {
                if (role.isPermitted(permission)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean[] hasRoles(List<String> roleIdentifiers) {
        boolean[] result;
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            int size = roleIdentifiers.size();
            result = new boolean[size];
            int i = 0;
            for (String roleName : roleIdentifiers) {
                result[i++] = hasRole(roleName);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean hasAllRoles(Collection<String> roleIdentifiers) {
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            for (String roleName : roleIdentifiers) {
                if (!hasRole(roleName)) {
                    return false;
                }
            }
        }
        return true;
    }

    public boolean[] isPermitted(List<Permission> permissions) {
        boolean[] result;
        if (permissions != null && !permissions.isEmpty()) {
            int size = permissions.size();
            result = new boolean[size];
            int i = 0;
            for (Permission p : permissions) {
                result[i++] = isPermitted(p);
            }
        } else {
            result = new boolean[0];
        }
        return result;
    }

    public boolean isPermittedAll(Collection<Permission> permissions) {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                if (!isPermitted(p)) {
                    return false;
                }
            }
        }
        return true;
    }

    public void checkPermission(Permission permission) throws AuthorizationException {
        if (!isPermitted(permission)) {
            String msg = "User is not permitted [" + permission + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkPermissions(Collection<Permission> permissions) throws AuthorizationException {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission p : permissions) {
                checkPermission(p);
            }
        }
    }

    public void checkRole(String role) {
        if (!hasRole(role)) {
            String msg = "User does not have role [" + role + "]";
            throw new UnauthorizedException(msg);
        }
    }

    public void checkRoles(Collection<String> roles) {
        if (roles != null && !roles.isEmpty()) {
            for (String roleName : roles) {
                checkRole(roleName);
            }
        }
    }
}