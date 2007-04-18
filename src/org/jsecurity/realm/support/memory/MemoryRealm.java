/*
* Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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


package org.jsecurity.realm.support.memory;

import org.jsecurity.JSecurityException;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.Permission;
import org.jsecurity.realm.support.AbstractRealm;
import org.jsecurity.realm.support.AuthorizationInfo;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.UsernamePrincipal;

import java.lang.reflect.Constructor;
import java.security.Principal;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * <p>A simple implementation of the {@link org.jsecurity.realm.Realm} interface that
 * uses a set of configured user accounts to authenticate the user.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and will be associated with users.</p>
 *
 * <p>See the <tt>applicationContext.xml</tt> in the Spring sample application for an example
 * of configuring a <tt>MemoryRealm</tt></p>
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class MemoryRealm extends AbstractRealm implements Initializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * A mapping between a user's principal and the user's authorization information.
     */
    private Map<Principal, AuthorizationInfo> authorizationInfoMap;

    private Set<AccountEntry> accounts;

    private Map<String,String> rolesPermissionsMap = new HashMap<String,String>();

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Sets the account entries that are used to authenticate users and associate them
     * with roles for this realm.
     * @param accounts the accounts for this realm.
     */
    public void setAccounts(Set<AccountEntry> accounts) {
        this.accounts = accounts;
    }


    /**
     * <p>A mapping of role names to permissions that can be authenticated using this realm.
     * It is not necessary to define any role entries if you are simply using
     * role-based authorization.  However if you want to use permission-based
     * authorization, you must define the permissions that apply to a particular
     * role.</p>
     *
     * <p>The key of the map is the role name.</p>
     *
     * <p>The value of the map is a delimited list of all permissions that apply to
     * this role.  Each permission entry is separated by semicolons.  Each
     * permission consists of a fully-qualified permission class-name, a
     * target name, and a list of actions that apply to the permission.  Each
     * of theses entries is comma-separated.</p>
     *
     * <p>For example,<br>
     * <tt>"com.mycompany.PermissionClass,myTarget,myAction1,myAction2,myAction3;<br>
     *     java.io.FilePermission,/myDir/myFile,read,write"</tt>
     * </p>
     *
     * @param rolesPermissionsMap the mapping between role names and permissions.
     */
    public void setRolesPermissionsMap(Map<String, String> rolesPermissionsMap) {
        this.rolesPermissionsMap = rolesPermissionsMap;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void init()  {
        if( accounts != null && !accounts.isEmpty() ) {

            Map<Principal, AuthorizationInfo> authorizationInfoMap = new HashMap<Principal, AuthorizationInfo>( accounts.size() );
            for( AccountEntry entry : accounts ) {

                String[] roleArray = entry.getRoles().split( "," );
                Set<String> roles = new HashSet<String>( roleArray.length );
                for( String role : roleArray ) {
                    roles.add( role.trim() );
                }

                Set<Permission> permissions = getPermissionsForRoles( roles );

                AuthorizationInfo info = new AuthorizationInfo( roles, permissions );
                authorizationInfoMap.put( new UsernamePrincipal( entry.getUsername() ), info );
            }
            this.authorizationInfoMap = authorizationInfoMap;
        }

    }

    /**
     * Builds a <tt>UserAuthenticationInfo</tt> object for the given username
     * by examining the set of configured accounts and roles held in the
     * memory realm.
     * @param token The authentication token that is being used to authenticate the current user.
     * @return an <tt>AuthenticationInfo</tt> object that represents the
     * authentication information for the given username, or null if an
     * account cannot be found with the given username.
     *
     */
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        Principal principal = token.getPrincipal();

        try {

            for( AccountEntry entry : accounts ) {
                if( entry.getUsername().equals( principal.getName() ) ) {
                    return new SimpleAuthenticationInfo( new UsernamePrincipal( principal.getName() ),
                                                  entry.getPassword().toCharArray() );

                }
            }

        } catch (Exception e) {
            throw new AuthenticationException( "Unexpected exception while authenticating user.", e );
        }

        // User could not be found, so return null
        return null;
    }


    private Set<Permission> getPermissionsForRoles(Set<String> roleNames) {

        Set<Permission> permissions = new HashSet<Permission>();

        for( String roleName : roleNames ) {
            String permissionsString = rolesPermissionsMap.get( roleName );

            // If the permissions String is not null or empty, parse the individual
            // permissions from it
            if( permissionsString != null && permissionsString.length() > 0 ) {
                Set<Permission> rolePermissions = parsePermissions( permissionsString );
                permissions.addAll( rolePermissions );
            }

        }

        return permissions;
    }


    private Set<Permission> parsePermissions(String permissionsString) {
        Set<Permission> rolePermissions = new HashSet<Permission>();

        // For each semicolon-delimited permission in the string, build
        // a permission object.
        String[] permissionsArray = permissionsString.split( ";" );
        for( String permissionString : permissionsArray ) {

            String[] permissionParts = permissionString.split( "," );
            if( permissionParts.length < 3 ) {
                throw new IllegalArgumentException(
                    "Permission token [" + permissionString + "] is not a valid permission " +
                    "definition.  Please see the JavaDoc for the " + getClass() + " class." );
            }

            // Parse permission string into class, target, and actions
            String clazz = permissionParts[0];
            String target = permissionParts[1];
            StringBuffer actions = new StringBuffer();
            for( int i = 2; i < permissionParts.length; i++ ) {
                actions.append( permissionParts[i] );
                if( permissionParts.length > (i+1) ) {
                    actions.append( "," );
                }
            }

            Permission permission = createPermission( clazz, target, actions.toString() );
            rolePermissions.add( permission );

        }

        return rolePermissions;
    }


    /**
     * Builds a permission object with the given class, target, and actions using reflection.
     * The permission class is expected to have a constructor that takes in two String
     * parameters.  The first parameter is the target of the permission.  The second parameter
     * is a comma-delimeted list of actions that apply to the permission.
     *
     * @param className the permission class.
     * @param target the permission target (or name).
     * @param actions the permission actions.
     * @return a new Permission object with the given properties.
     */
    private Permission createPermission(String className, String target, String actions) {

        try {
            Class clazz = Class.forName( className );
            Constructor constructor = clazz.getConstructor( String.class, String.class );
            return (Permission) constructor.newInstance( target, actions );
        } catch (Exception e) {
            throw new JSecurityException( "Error instantiating permission specified for realm [" + getName() + "]", e );
        }

    }


    protected AuthorizationInfo getAuthorizationInfo(Principal principal) {
        return authorizationInfoMap.get( principal );
    }

}