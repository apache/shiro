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
package org.jsecurity.realm;

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authz.AuthorizingAccount;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.SimpleAuthorizingAccount;
import org.jsecurity.authz.SimpleRole;
import org.jsecurity.cache.Cache;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.HashtableCacheProvider;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.LifecycleUtils;
import org.jsecurity.util.PermissionUtils;

import java.util.*;

/**
 * <p>A simple implementation of the {@link org.jsecurity.realm.Realm Realm} interface that
 * uses a set of configured user accounts and roles to support authentication and authorization.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and associated with users.</p>
 *
 * <p>User accounts and roles are stored in two {@link Cache cache}s, so it is the Cache provider implementation that
 * determines if this class stores all data in memory or spools to disk or clusters it, etc.
 *
 * <p>User accounts can be specified in a couple of ways:
 *
 * <ul>
 *   <li>Specifying a Map of username-to-password&amp;rolenames via the
 *   {@link #setUserDefinitions(java.util.Map) setUserDefinitions(Map)} method.</li>
 *   <li>Specifying a list of strings of username-to-password&amp;rolenames assignments.  The format of each line
 *   is specified in the {@link #setUserDefinitions(java.util.List) setUserDefinitions(List)} JavaDoc.  This mechanism
 *   is just a convenience helper for the Map equivalent.</li>
 * </ul>
 *
 * <p>Roles and associated permissions can be specified similarly:
 *
 * <ul>
 *   <li>Specifying a Map of rolename-to-permission(s) via the
 *   {@link #setRoleDefinitions(java.util.Map) setRoleDefinitions(Map)} method.</li>
 *   <li>Specifying a list of strings of rolename-to-password(s) assignments.  The format of each line
 *   is specified in the {@link #setRoleDefinitions(java.util.List) setRoleDefinitions(List)} JavaDoc.  This mechanism
 *   is just a convenience helper for the Map equivalent.</li>
 * </ul>
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SimpleAccountRealm extends AuthorizingRealm implements Initializable, Destroyable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final String USER_ROLENAME_DELIMITER = ",";
    private static final String PERMISSION_DELIMITER = ",";
    
    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected Cache userCache = null;
    protected Cache roleCache = null;

    private Map<String,String> userDefinitions = null;
    private Map<String,String> roleDefinitions = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    public SimpleAccountRealm() {
        //this class maintains its own userCache and roleCache - no need for parent class to do so also:
        setAccountCacheEnabled(false);
    }

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
     * abrown = <em>abrownsPassword</em>,qa,employee<br/>
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
     * abrown : <em>abrownsPassword</em>,qa,employee<br/>
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
     * <p><code><em>rolename</em> : <em>permissionDefinition1</em>,<em>permissionDefinition2</em>,...</code></p>
     *
     * <p>Each Map.Entry value must specify one or more comma-delimited <em>permissionDefinition</em>s.
     *
     * <p>A <em>permissionDefinition</em> is an arbitrary String, but must people will want to use
     * Strings that conform to the {@link org.jsecurity.authz.permission.WildcardPermission WildcardPermission}
     * string format for ease of use and flexibility.</p>
     *
     * <p>Note that if an individual <em>permissionDefnition</em> needs to be internally comma-delimited, you will need
     * to surround that definition with double quotes (&quot;) to avoid parsing errors.
     *
     * <p><b>PLEASE NOTE</b> that if you have roles that don't require permission associations, don't include them in this
     * list - just defining the role name in a {@link #setUserDefinitions(java.util.Map) user definition} is enough to create the
     * role if it does not yet exist.
     *
     * @param roleDefinitions the role definitions to be parsed at initialization
     */
    public void setRoleDefinitions( Map<String,String> roleDefinitions ) {
        this.roleDefinitions = roleDefinitions;
    }

    protected SimpleAuthorizingAccount getUser( String username ) {
        return (SimpleAuthorizingAccount)userCache.get( username );
    }

    protected void add( SimpleAuthorizingAccount user ) {
        userCache.put( user.getPrincipal(), user );
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


            SimpleAuthorizingAccount user = getUser( username );
            if ( user == null ) {
                user = new SimpleAuthorizingAccount( username, password );
                add( user );
            }
            user.setCredentials( password );

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

            Set<Permission> permissions = PermissionUtils.resolveDelimitedPermissions( value, getPermissionResolver(), PERMISSION_DELIMITER );
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
    public void onInit() {
        initUserAndRoleCaches();
    }

    protected void initUserAndRoleCaches() {
        CacheProvider provider = getCacheProvider();

        if ( provider == null ) {
            provider = new HashtableCacheProvider();
            setCacheProvider( provider );
        }

        this.userCache = provider.buildCache( getClass().getName() + ".users" );
        this.roleCache = provider.buildCache( getClass().getName() + ".roles" );

        processRoleDefinitions();
        processUserDefinitions();
    }


    public void destroy() {
        LifecycleUtils.destroy(userCache);
        this.userCache = null;
        LifecycleUtils.destroy(roleCache);
        this.roleCache = null;
        super.destroy();
    }

    protected AuthorizingAccount doGetAccount(Object principal) {
        return (SimpleAuthorizingAccount)userCache.get(principal);
    }

    protected Account doGetAccount( AuthenticationToken token ) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken)token;
        return doGetAccount( upToken.getUsername() );
    }
}