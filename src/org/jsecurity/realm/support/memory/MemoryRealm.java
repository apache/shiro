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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.support.HashtableCacheProvider;
import org.jsecurity.realm.support.AuthenticatingRealm;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.PermissionUtils;
import org.jsecurity.util.UsernamePrincipal;

import java.security.Principal;
import java.util.*;

/**
 * <p>A simple implementation of the {@link org.jsecurity.realm.Realm Realm} interface that
 * uses a set of configured user accounts and roles to support authentication and authorization.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and associated with users.</p>
 *
 * <p>User accounts can be specified in a couple of ways:
 *
 * <ul>
 *   <li>Specifying a Map of username-to-password&amp;rolenames via the
 *   {@link #setUserDefinitions(Map) setUserDefinitions(Map)} method.</li>
 *   <li>Specifying a list of strings of username-to-password&amp;rolenames assignments.  The format of each line
 *   is specified in the {@link #setUserDefinitions( List ) setUserDefinitions( List )} JavaDoc.  This mechanism
 *   is just a convenience helper for the Map equivalent.</li>
 * </ul>
 *
 * <p>Roles and associated permissions can be specified similarly:
 *
 * <ul>
 *   <li>Specifying a Map of rolename-to-permission(s) via the
 *   {@link #setRoleDefinitions(Map) setRoleDefinitions(Map)} method.</li>
 *   <li>Specifying a list of strings of rolename-to-password(s) assignments.  The format of each line
 *   is specified in the {@link #setRoleDefinitions( List ) setRoleDefinitions( List )} JavaDoc.  This mechanism
 *   is just a convenience helper for the Map equivalent.</li>
 * </ul>
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class MemoryRealm extends AuthenticatingRealm implements Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final String USER_ROLENAME_DELIMITER = ",";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected Cache userCache = null;
    protected Cache roleCache = null;

    private boolean cacheProviderImplicitlyCreated = true;

    private Map<String,String> userDefinitions = null;
    private Map<String,String> roleDefinitions = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    /**
     * Convenience method that converts a list of Strings into Map.Entry elements for the
     * {@link #setUserDefinitions(Map) setUserDefinitions(Map)} method.  This allows one to specify user configuration
     * with simple strings and pass them directly to this instance if desired.
     *
     * <p>Each List element must be a String that defines a user-to-password&amp;role(s) key/value mapping according 
     * to the {@link #setUserDefinitions(Map) setUserDefinitions(Map)} JavaDoc.  The only difference here is that an
     * equals character signifies the key/value separation, like so:</p>
     *
     * <p><code><em>username</em> = <em>password</em>,role1,role2,...</code></p>
     *
     * <p>Here are some examples of what these lines might look like:</p>
     *
     * <p><code>root = <em>reallyHardToGuessPassword</em>,administrator<br/>
     * jsmith = <em>jsmithsPassword</em>,manager,engineer,employee<br/>
     * abrown = <em>dbrownsPassword</em>,qa,employee<br/>
     * djones = <em>djonesPassword</em>,qa,contractor<br/>
     * guest = <em>guestPassword</em></code></p>
     *
     * @param userDefinitions the user definitions to be parsed and converted to Map.Entry elements
     */
    public void setUserDefinitions( List<String> userDefinitions ) {
        setUserDefinitions( toMap( userDefinitions ) );
    }

    /**
     * Convenience method that converts a list of Strings into Map.Entry elements for the
     * {@link #setRoleDefinitions(Map) setRoleDefinitions(Map)} method.  This allows one to specify role configuration
     * with simple strings and pass them directly to this instance if desired.
     *
     * <p>Each List element must be a String that defines a role-to-permission(s) key/value mapping according
     * to the {@link #setRoleDefinitions(Map) setRoleDefinitions(Map)} JavaDoc.  The only difference here is that an
     * equals character signifies the key/value separation, like so:</p>
     *
     * <p><code><em>rolename</em> = <em>permissionDefinition1</em>;<em>permissionDefinition2</em>;...</code></p>
     *
     * <p>Please see the {@link #setRoleDefinitions(Map) setRoleDefinitions(Map)} JavaDoc for complete reference on
     * what each of these line elements mean.
     *
     * <p><b>PLEASE NOTE</b> that if you have roles that don't require permission associations, don't include them in
     * this list - just defining the role name in a {@link #setUserDefinitions user definition} is enough to create the
     * role if it does not yet exist.
     *
     * @param roleDefinitions the role definitions to be parsed and converted to Map.Entry elements
     */
    public void setRoleDefinitions( List<String> roleDefinitions ) {
        if ( roleDefinitions == null || roleDefinitions.isEmpty() ) {
            return;
        }
        setRoleDefinitions( toMap( roleDefinitions ) );
    }

    public Map<String,String> getUserDefinitions() {
        return userDefinitions;
    }

    /**
     * Sets the user definitions to be parsed and converted into internal User accounts.
     *
     * <p>Each Map.Entry must be a username (key) to password&amp;role(s) (value) mapping like the following:</p>
     *
     * <p><code><em>username</em> : <em>password</em>,role1,role2,...</code></p>
     *
     * <p>Each Map.Entry value must specify that user's password followed by
     * zero or more comma-delimited role names of the roles assigned to that user.</p>
     *
     * <p>Here are some examples of what these Map.Entry elements might look like:</p>
     *
     * <p><code>root : <em>reallyHardToGuessPassword</em>,administrator<br/>
     * jsmith : <em>jsmithsPassword</em>,manager,engineer,employee<br/>
     * abrown : <em>dbrownsPassword</em>,qa,employee<br/>
     * djones : <em>djonesPassword</em>,qa,contractor<br/>
     * guest : <em>guestPassword</em></code></p>
     *
     * @param userDefinitions the user definitions to be parsed at initialization
     */
    public void setUserDefinitions( Map<String,String> userDefinitions ) {
        this.userDefinitions = userDefinitions;
    }

    public Map<String,String> getRoleDefinitions() {
        return roleDefinitions;
    }

    /**
     * Sets the role definitions to be parsed and converted to internal Role representations.
     *
     * <p>Each Map.Entry must be a rolename (key) to permission(s) (value) mapping like the following:</p>
     *
     * <p><code><em>rolename</em> : <em>permissionDefinition1</em>;<em>permissionDefinition2</em>;...</code></p>
     *
     * <p>Each Map.Entry value must specify one or more <em>permissionDefinition</em>s.  A <em>permissionDefinition</em>
     * is defined as</p>
     *
     * <p><code><em>requiredPermissionClassName</em>,<em>requiredPermissionName</em>,<em>optionalActionsString</em></code></p>
     *
     * <p>corresponding to the associated class attributes of
     * {@link org.jsecurity.authz.Permission Permission} or
     * {@link org.jsecurity.authz.TargetedPermission TargetedPermission}.</p>
     *
     * <p><em>optionalActionsString</em> is optional as implied, but if it exists, it <em>is</em> allowed to contain
     * commas as well.
     *
     * <p>But note that because a single <em>permissionDefinition</em> is internally delimited via commas (,), multiple
     * <em>permissionDefinition</em>s for a single role must be delimited via semi-colons (;)
     *
     * <p><b>PLEASE NOTE</b> that if you have roles that don't require permission associations, don't include them in this
     * list - just defining the role name in a {@link #setUserDefinitions(Map) user definition} is enough to create the
     * role if it does not yet exist.
     *
     * @param roleDefinitions the role definitions to be parsed at initialization
     */
    public void setRoleDefinitions( Map<String,String> roleDefinitions ) {
        this.roleDefinitions = roleDefinitions;
    }

    protected SimpleUser getUser( String username ) {
        return (SimpleUser)userCache.get( username );
    }

    protected void add( SimpleUser user ) {
        userCache.put( user.getUsername(), user );
    }

    protected SimpleRole getRole( String rolename ) {
        return (SimpleRole)roleCache.get( rolename );
    }

    protected void add( SimpleRole role ) {
        roleCache.put( role.getName(), role );
    }

    protected static Set<String> toSet( String delimited, String delimiter ) {
        if ( delimited == null || delimited.trim().equals( "" ) ) {
            return null;
        }

        Set<String> values = new HashSet<String>();
        String[] rolenamesArray = delimited.split( delimiter );
        for ( String s : rolenamesArray ) {
            String trimmed = s.trim();
            if ( trimmed.length() > 0 ) {
                values.add( trimmed );
            }
        }

        return values;
    }

    protected void processUserDefinitions() {

        Map<String,String> userDefs = getUserDefinitions();
        if ( userDefs == null || userDefs.isEmpty() ) {
            return;
        }

        for ( String username : userDefs.keySet() ) {

            String value = userDefs.get( username );

            String[] passwordAndRolesArray = value.split( USER_ROLENAME_DELIMITER, 2 );
            String password = passwordAndRolesArray[0];


            SimpleUser user = getUser( username );
            if ( user == null ) {
                user = new SimpleUser( username, password );
                add( user );
            }
            user.setPassword( password );

            Set<String> valueRolenames;
            if ( passwordAndRolesArray.length > 1 ) {
                valueRolenames = toSet( passwordAndRolesArray[1], USER_ROLENAME_DELIMITER );
                if ( valueRolenames != null && !valueRolenames.isEmpty() ) {
                    for ( String rolename : valueRolenames ) {
                        SimpleRole role = getRole( rolename );
                        if ( role == null ) {
                            role = new SimpleRole( rolename );
                            add( role );
                        }
                        user.add( role );
                    }
                } else {
                    user.setRoles( null );
                }
            } else {
                user.setRoles( null );
            }
        }
    }

    protected void processRoleDefinitions() {

        Map<String,String> roleDefs = getRoleDefinitions();
        if ( roleDefs == null || roleDefs.isEmpty() ) {
            return;
        }

        for ( String rolename : roleDefs.keySet() ) {
            String value = roleDefs.get( rolename );

            SimpleRole role = getRole( rolename );
            if ( role == null ) {
                role = new SimpleRole( rolename );
                add( role );
            }

            Set<Permission> permissions = PermissionUtils.createPermissions( value );
            role.setPermissions( permissions );
        }
    }

    protected Map<String,String> toMap( List<String> keyValuePairs ) {
        if ( keyValuePairs == null || keyValuePairs.isEmpty() ) {
            return null;
        }

        Map<String,String> pairs = new HashMap<String,String>();

        for( String pairString : keyValuePairs ) {
            if ( !pairString.contains( "=" ) ) {
                String msg = "Invalid definition entry [" + pairString + "].  Key/Value pairs must be separated " +
                    "by an equals character (=)";
                throw new IllegalArgumentException( msg );
            }
            String[] pair = pairString.split( "=", 2 );
            pairs.put( pair[0].trim(), pair[1].trim() );
        }
        
        return pairs;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void init() {
        CacheProvider provider = getCacheProvider();

        if ( provider == null ) {
            provider = new HashtableCacheProvider();
            setCacheProvider( provider );
            this.cacheProviderImplicitlyCreated = true;
        }

        this.userCache = provider.buildCache( getClass().getName() + ".users" );
        this.roleCache = provider.buildCache( getClass().getName() + ".roles" );

        processUserDefinitions();
        processRoleDefinitions();
    }

    protected void destroy( Cache cache ) {
        if ( cache != null ) {
            try {
                cache.clear();
            } catch ( Throwable t ) {
                if ( log.isInfoEnabled() ) {
                    log.info( "Unable to cleanly clear cache [" + cache + "].  Ingoring (shutting down)." );
                }
            }
            try {
                cache.destroy();
            } catch ( CacheException e ) {
                if ( log.isInfoEnabled() ) {
                    log.info( "Unable to cleanly destroy cache [" + cache + "].  Ignoring (shutting down)." );
                }
            }

        }
    }

    public void destroy() throws Exception {
        destroy( userCache );
        destroy( roleCache );
        if ( this.cacheProviderImplicitlyCreated ) {
            if ( getCacheProvider() instanceof Destroyable ) {
                try {
                    ( (Destroyable)getCacheProvider() ).destroy();
                } catch ( Exception e ) {
                    if ( log.isInfoEnabled() ) {
                        log.info( "Unable to cleanly destroy implicitly created CacheProvider.  Ignoring (shutting down)" );
                    }
                }
            }
        }
    }

    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;

        SimpleUser user = (SimpleUser)userCache.get( upToken.getUsername() );
        if ( user == null ) {
            return null;
        }

        Principal principal = new UsernamePrincipal( user.getUsername() );

        return new SimpleAuthenticationInfo( principal, user.getPassword() );

    }

    protected String getUsername( Principal principal ) {
        if ( principal instanceof UsernamePrincipal ) {
            return ( (UsernamePrincipal)principal ).getUsername();
        } else {
            String msg = "The " + getClass().getName() + " implementation expects all Principal arguments to be " +
                "instances of the [" + UsernamePrincipal.class.getName() + "] class";
            throw new IllegalArgumentException( msg );
        }
    }

    protected SimpleUser getUser( Principal principal ) {
        return getUser( getUsername( principal ) );
    }

    public boolean hasRole( Principal principal, String roleIdentifier ) {
        SimpleUser user = getUser( principal );
        return ( user != null && user.hasRole( roleIdentifier ) );
    }


    public boolean[] hasRoles( Principal principal, List<String> roleIdentifiers ) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];
        for ( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( principal, roleIdentifiers.get( i ) );
        }
        return hasRoles;
    }

    public boolean hasAllRoles( Principal principal, Collection<String> roleIdentifiers ) {
        for ( String rolename : roleIdentifiers ) {
            if ( !hasRole( principal, rolename ) ) {
                return false;
            }
        }
        return true;
    }

    public boolean isPermitted( Principal principal, Permission permission ) {
        SimpleUser user = getUser( principal );
        return user != null && user.isPermitted( permission );
    }

    public boolean[] isPermitted( Principal principal, List<Permission> permissions ) {
        boolean[] permitted = new boolean[permissions.size()];
        for ( int i = 0; i < permissions.size(); i++ ) {
            permitted[i] = isPermitted( principal, permissions.get( i ) );
        }
        return permitted;
    }

    public boolean isPermittedAll( Principal principal, Collection<Permission> permissions ) {
        for ( Permission perm : permissions ) {
            if ( !isPermitted( principal, perm ) ) {
                return false;
            }
        }
        return true;
    }

    public void checkPermission( Principal principal, Permission permission ) throws AuthorizationException {
        if ( !isPermitted( principal, permission ) ) {
            throw new UnauthorizedException( "User does not have permission [" + permission + "]" );
        }
    }

    public void checkPermissions( Principal principal, Collection<Permission> permissions ) throws AuthorizationException {
        if ( permissions != null ) {
            for ( Permission permission : permissions ) {
                if ( !isPermitted( principal, permission ) ) {
                    throw new UnauthorizedException( "User does not have permission [" + permission + "]" );
                }
            }
        }
    }

    public void checkRole( Principal principal, String role ) throws AuthorizationException {
        if ( !hasRole( principal, role ) ) {
            throw new UnauthorizedException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles( Principal principal, Collection<String> roles ) throws AuthorizationException {
        if ( roles != null ) {
            for ( String role : roles ) {
                if ( !hasRole( principal, role ) ) {
                    throw new UnauthorizedException( "User does not have role [" + role + "]" );
                }
            }
        }
    }

    /**
     * Default implementation that always returns <tt>true</tt> (defers on JSecurity's JDK 1.5 annotations).
     *
     * @param action the action to check for authorized execution
     * @return whether or not the realm supports AuthorizedActions of the given type.
     */
    public boolean supports( AuthorizedAction action ) {
        return true;
    }

    /**
     * Default implementation always returns <tt>true</tt>.
     */
    public boolean isAuthorized( Principal subjectIdentifier, AuthorizedAction action ) {
        return true;
    }

    /**
     * Default implementation always returns quietly (no exception thrown).
     */
    public void checkAuthorization( Principal subjectIdentifier, AuthorizedAction action ) throws AuthorizationException {
        //does nothing
    }

}