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
package org.jsecurity.realm.support.jdbc;

import org.jsecurity.authc.*;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizationInfo;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.support.SimpleAuthorizationInfo;
import org.jsecurity.realm.support.AuthorizingRealm;
import org.jsecurity.util.JdbcUtils;
import org.jsecurity.util.PermissionUtils;
import org.jsecurity.util.UsernamePrincipal;

import javax.sql.DataSource;
import java.security.Principal;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashSet;

/**
 * <p>
 * Realm that allows authentication and authorization via JDBC calls.  The default queries suggest a potential schema
 * for retrieving the user's password for authentication, and querying for a user's roles and permissions.  The
 * default queries can be overridden by setting the query properties of the realm.
 * </p>
 *
 * <p>
 * If the default implementation
 * of authentication and authorization cannot handle your schema, this class can be subclassed and the
 * appropriate methods overridden. (usually {@link #doGetAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)},
 * {@link #getRoleNamesForUser(java.sql.Connection,String)}, and/or {@link #getPermissions(java.sql.Connection,String,java.util.Collection)}
 * </p>
 *
 * <p>
 * This realm supports caching by extending from {@link org.jsecurity.realm.support.AuthorizingRealm}.
 * </p>
 *
 * @since 0.2
 * @author Jeremy Haile
 */
public class JdbcRealm extends AuthorizingRealm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    /**
     * The default query used to retrieve authentication information for the user.
     */
    protected static final String DEFAULT_AUTHENTICATION_QUERY = "select password from users where username = ?";

    /**
     * The default query used to retrieve the roles that apply to a user.
     */
    protected static final String DEFAULT_USER_ROLES_QUERY = "select role_name from user_roles where username = ?";

    /**
     * The default query used to retrieve permissions that apply to a particular role.
     */
    protected static final String DEFAULT_PERMISSIONS_QUERY = "select permission_class, permission_target, permission_actions from roles_permissions where role_name = ?";


    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected DataSource dataSource;

    protected String authenticationQuery = DEFAULT_AUTHENTICATION_QUERY;

    protected String userRolesQuery = DEFAULT_USER_ROLES_QUERY;

    protected String permissionsQuery = DEFAULT_PERMISSIONS_QUERY;

    protected boolean permissionsLookupEnabled = false;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets the datasource that should be used to retrieve connections used by this realm.
     *
     * @param dataSource the SQL data source.
     */
    public void setDataSource( DataSource dataSource ) {
        this.dataSource = dataSource;
    }

    /**
     * Overrides the default query used to retrieve a user's password during authentication.  When using the default
     * implementation, this query must take the user's username as a single parameter and return a single result
     * with the user's password as the first column.  If you require a solution that does not match this query
     * structure, you can override {@link #doGetAuthenticationInfo(org.jsecurity.authc.AuthenticationToken)} or
     * just {@link #getPasswordForUser(java.sql.Connection,String)}
     *
     * @param authenticationQuery the query to use for authentication.
     * @see #DEFAULT_AUTHENTICATION_QUERY
     */
    public void setAuthenticationQuery( String authenticationQuery ) {
        this.authenticationQuery = authenticationQuery;
    }

    /**
     * Overrides the default query used to retrieve a user's roles during authorization.  When using the default
     * implementation, this query must take the user's username as a single parameter and return a row
     * per role with a single column containing the role name.  If you require a solution that does not match this query
     * structure, you can override {@link #doGetAuthorizationInfo(java.security.Principal)} or just
     * {@link #getRoleNamesForUser(java.sql.Connection,String)}
     *
     * @param userRolesQuery the query to use for retrieving a user's roles.
     * @see #DEFAULT_USER_ROLES_QUERY
     */
    public void setUserRolesQuery( String userRolesQuery ) {
        this.userRolesQuery = userRolesQuery;
    }

    /**
     * <p>
     * Overrides the default query used to retrieve a user's permissions during authorization.  When using the default
     * implementation, this query must take a role name as the single parameter and return a row
     * per permission with three columns containing the fully qualified name of the permission class, the permission
     * name, and the permission actions (in that order).  If you require a solution that does not match this query
     * structure, you can override {@link #doGetAuthorizationInfo(java.security.Principal)} or just
     * {@link #getPermissions(java.sql.Connection,String,java.util.Collection)}</p>
     *
     * <p><b>Permissions are only retrieved if you set {@link #permissionsLookupEnabled} to true.  Otherwise,
     * this query is ignored.</b></p>
     *
     * @param permissionsQuery the query to use for retrieving permissions for a role.
     * @see #DEFAULT_PERMISSIONS_QUERY
     * @see #setPermissionsLookupEnabled(boolean)
     */
    public void setPermissionsQuery( String permissionsQuery ) {
        this.permissionsQuery = permissionsQuery;
    }

    /**
     * Enables lookup of permissions during authorization.  The default is "false" - meaning that only roles
     * are associated with a user.  Set this to true in order to lookup roles <b>and</b> permissions.
     *
     * @param permissionsLookupEnabled true if permissions should be looked up during authorization, or false if only
     *                                 roles should be looked up.
     */
    public void setPermissionsLookupEnabled( boolean permissionsLookupEnabled ) {
        this.permissionsLookupEnabled = permissionsLookupEnabled;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    public void onInit() {
        setAuthenticationTokenClass( UsernamePasswordToken.class );
    }

    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {

        UsernamePasswordToken upToken = (UsernamePasswordToken)token;
        String username = upToken.getUsername();

        // Null username is invalid
        if ( username == null ) {
            throw new AccountException( "Null usernames are not allowed by this realm." );
        }

        Connection conn = null;
        SimpleAuthenticationInfo info = null;
        try {
            conn = dataSource.getConnection();

            String password = getPasswordForUser( conn, username );

            if ( password == null ) {
                throw new UnknownAccountException( "No account found for user [" + username + "]" );
            }

            info = new SimpleAuthenticationInfo();

            // Populate the authentication info
            info.addPrincipal( new UsernamePrincipal( username ) );
            info.setCredentials( password );

        } catch ( SQLException e ) {
            final String message = "There was a SQL error while authenticating user [" + username + "]";
            if ( log.isErrorEnabled() ) {
                log.error( message, e );
            }

            // Rethrow any SQL errors as an authentication exception
            throw new AuthenticationException( message, e );
        } finally {
            JdbcUtils.closeConnection( conn );
        }

        return info;
    }

    private String getPasswordForUser( Connection conn, String username ) throws SQLException {

        PreparedStatement ps = null;
        ResultSet rs = null;
        String password = null;
        try {
            ps = conn.prepareStatement( authenticationQuery );
            ps.setString( 1, username );

            // Execute query
            rs = ps.executeQuery();

            // Loop over results - although we are only expecting one result, since usernames should be unique
            boolean foundResult = false;
            while ( rs.next() ) {

                // Check to ensure only one row is processed
                if ( foundResult ) {
                    throw new AuthenticationException( "More than one user row found for user [" + username + "]. Usernames must be unique." );
                }

                password = rs.getString( 1 );

                foundResult = true;
            }
        } finally {
            JdbcUtils.closeResultSet( rs );
            JdbcUtils.closeStatement( ps );
        }

        return password;
    }

    protected AuthorizationInfo doGetAuthorizationInfo( Principal principal ) {

        UsernamePrincipal usernamePrincipal = (UsernamePrincipal)principal;
        String username = usernamePrincipal.getUsername();

        // Null username is invalid
        if ( username == null ) {
            throw new AuthorizationException( "Null usernames are not allowed by this realm." );
        }

        Connection conn = null;
        Collection<String> roleNames = null;
        Collection<Permission> permissions = null;
        try {
            conn = dataSource.getConnection();

            // Retrieve roles and permissions from database
            roleNames = getRoleNamesForUser( conn, username );
            permissions = getPermissions( conn, username, roleNames );

        } catch ( SQLException e ) {
            final String message = "There was a SQL error while authorizing user [" + username + "]";
            if ( log.isErrorEnabled() ) {
                log.error( message, e );
            }

            // Rethrow any SQL errors as an authorization exception
            throw new AuthorizationException( message, e );
        } finally {
            JdbcUtils.closeConnection( conn );
        }

        return new SimpleAuthorizationInfo( roleNames, permissions );
    }

    protected Collection<String> getRoleNamesForUser( Connection conn, String username ) throws SQLException {
        PreparedStatement ps = null;
        ResultSet rs = null;
        Collection<String> roleNames = new HashSet<String>();
        try {
            ps = conn.prepareStatement( userRolesQuery );
            ps.setString( 1, username );

            // Execute query
            rs = ps.executeQuery();

            // Loop over results and add each returned role to a set
            while ( rs.next() ) {

                String roleName = rs.getString( 1 );

                // Add the role to the list of names if it isn't null
                if ( roleName != null ) {
                    roleNames.add( roleName );
                } else {
                    if ( log.isWarnEnabled() ) {
                        log.warn( "Null role name found while retrieving role names for user [" + username + "]" );
                    }
                }
            }
        } finally {
            JdbcUtils.closeResultSet( rs );
            JdbcUtils.closeStatement( ps );
        }
        return roleNames;
    }

    protected Collection<Permission> getPermissions( Connection conn, String username, Collection<String> roleNames ) throws SQLException {
        PreparedStatement ps = null;
        ResultSet rs = null;
        Collection<Permission> permissions = new HashSet<Permission>();
        try {
            for ( String roleName : roleNames ) {

                ps = conn.prepareStatement( permissionsQuery );
                ps.setString( 1, roleName );

                // Execute query
                rs = ps.executeQuery();

                // Loop over results and add each returned role to a set
                while ( rs.next() ) {

                    String className = rs.getString( 1 );
                    String target = rs.getString( 2 );
                    String actions = rs.getString( 3 );

                    // Instantiate a permission object using reflection
                    Permission permission = PermissionUtils.createPermission( className, target, actions );

                    // Add the permission to the set of permissions
                    permissions.add( permission );
                }

            }
        } finally {
            JdbcUtils.closeResultSet( rs );
            JdbcUtils.closeStatement( ps );
        }

        return permissions;
    }

}