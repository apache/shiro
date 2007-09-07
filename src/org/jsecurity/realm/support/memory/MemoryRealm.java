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
 * <p>A simple implementation of the {@link org.jsecurity.realm.Realm} interface that
 * uses a set of configured user accounts to authenticate the user.  Each account entry
 * specifies the username, password, and roles for a user.  Roles can also be mapped
 * to permissions and will be associated with users.</p>
 *
 * <p>See the <tt>applicationContext.xml</tt> in the Spring sample application for an example
 * of configuring a <tt>MemoryRealm</tt></p>
 *
 * TODO - clean up this JavaDoc to document the text format
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

    private Properties userProperties = null;
    private Properties roleProperties = null;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Sets the user definitions to be parsed and converted to Properties entries.
     *
     * <p>Each definition must be a user-to-role(s) key/value mapping with the following format:</p>
     *
     * <p><code><em>username1</em> = <em>password1</em>,role1,role2,...</code></p>
     *
     * <p>Each value (the text to the right of the equals character) must specify that user's password followed by
     * zero or more role names of the roles assigned to that user.</p>
     *
     * <p>Here are some examples of what these lines might look like:</p>
     *
     * <p><code>root = <em>reallyHardToGuessPassword</em>,administrator<br/>
     * jsmith = <em>jsmithsPassword</em>,manager,engineer,employee<br/>
     * abrown = <em>dbrownsPassword</em>,qa,employee<br/>
     * djones = <em>djonesPassword</em>,qa,contractor<br/>
     * guest = <em>guestPassword</em></code></p>
     *
     * @param userDefinitions the user definitions to be parsed at initialization
     */
    public void setUserDefinitions( List<String> userDefinitions ) {
        if ( userDefinitions == null || userDefinitions.isEmpty() ) {
            return;
        }
        setUserProperties( toProperties( userDefinitions ) );
    }

    /**
     * Sets the role definitions to be parsed and converted to Properteis entries.
     *
     * <p>Each definition must be a role-to-permission(s) key/value mapping with the following format:</p>
     *
     * <p><code><em>rolename1</em> = <em>permissionDefinition1</em>;<em>permissionDefinition2</em>;...</code></p>
     *
     * <p>Each value (the text to the right of the equals character) must specify one or more
     * <em>permissionDefinition</em>s.  A <em>permissionDefinition</em> is defined as</p>
     *
     * <p><code><em>requiredPermissionClassName</em>,<em>requiredPermissionName</em>,<em>optionalActionsString</em></code></p>
     *
     * <p>corresponding to the associated class attributes of a
     * {@link org.jsecurity.authz.Permission Permission} or
     * {@link org.jsecurity.authz.TargetedPermission TargetedPermission}.</p>
     *
     * <p><em>optionalActionsString</em> is optional as implied, but if it exists, it <em>is</em> allowed to contain
     * commas as well.
     *
     * But note that because a single <em>permissionDefinition</em> is internally delimited via commas (,), multiple
     * <em>permissionDefinition</em>s for a single role must be delimited via semi-colons (;)
     *
     * <p><b>Note</b> that if you have roles that don't require permission associations, don't include them in this
     * list - just defining the role name in a {@link #setUserDefinitions user definition} is enough to create the
     * role if it does not yet exist.
     *
     * @param roleDefinitions the role definitions to be parsed at initialization
     */
    public void setRoleDefinitions( List<String> roleDefinitions ) {
        if ( roleDefinitions == null || roleDefinitions.isEmpty() ) {
            return;
        }
        setRoleProperties( toProperties( roleDefinitions ) );
    }

    public Properties getUserProperties() {
        return userProperties;
    }

    public void setUserProperties( Properties userProperties ) {
        this.userProperties = userProperties;
    }

    public Properties getRoleProperties() {
        return roleProperties;
    }

    public void setRoleProperties( Properties roleProperties ) {
        this.roleProperties = roleProperties;
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

    protected void processUserProperties() {

        Properties userProps = getUserProperties();
        if ( userProps == null || userProps.isEmpty() ) {
            return;
        }

        //noinspection unchecked
        Enumeration<String> propNames = (Enumeration<String>)userProps.propertyNames();

        while ( propNames.hasMoreElements() ) {

            String username = propNames.nextElement();
            String value = userProps.getProperty( username );

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

    protected void processRoleProperties() {
        Properties roleProps = getRoleProperties();
        if ( roleProps == null || roleProps.isEmpty() ) {
            return;
        }

        //noinspection unchecked
        Enumeration<String> propNames = (Enumeration<String>)roleProps.propertyNames();

        while ( propNames.hasMoreElements() ) {
            String rolename = propNames.nextElement();
            String value = roleProps.getProperty( rolename );

            SimpleRole role = getRole( rolename );
            if ( role == null ) {
                role = new SimpleRole( rolename );
                add( role );
            }

            Set<Permission> permissions = PermissionUtils.createPermissions( value );
            role.setPermissions( permissions );
        }
    }

    protected Properties toProperties( List<String> keyValuePairs ) {
        if ( keyValuePairs == null || keyValuePairs.isEmpty() ) {
            return null;
        }

        Properties props = new Properties();

        for( String pairString : keyValuePairs ) {
            if ( !pairString.contains( "=" ) ) {
                String msg = "Invalid definition entry [" + pairString + "].  Key/Value pairs must be separated " +
                    "by an equals character (=)";
                throw new IllegalArgumentException( msg );
            }
            String[] pair = pairString.split( "=", 2 );
            props.setProperty( pair[0].trim(), pair[1].trim() );
        }
        
        return props;
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

        processUserProperties();
        processRoleProperties();
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
     * Default implementation that always returns false (relies on JSecurity 1.5 annotations instead).
     *
     * @param action the action to check for authorized execution
     * @return whether or not the realm supports AuthorizedActions of the given type.
     */
    public boolean supports( AuthorizedAction action ) {
        return false;
    }

    public boolean isAuthorized( Principal subjectIdentifier, AuthorizedAction action ) {
        return true;
    }

    public void checkAuthorization( Principal subjectIdentifier, AuthorizedAction action ) throws AuthorizationException {
        //does nothing
    }

}