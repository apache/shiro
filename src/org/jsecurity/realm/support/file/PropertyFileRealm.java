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

package org.jsecurity.realm.support.file;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.JSecurityException;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.support.SimpleAuthenticationInfo;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.AuthorizedAction;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.UnauthorizedException;
import org.jsecurity.realm.support.AuthenticatingRealm;
import org.jsecurity.realm.support.memory.SimpleRole;
import org.jsecurity.realm.support.memory.SimpleUser;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.PermissionUtils;
import org.jsecurity.util.ResourceUtils;
import org.jsecurity.util.UsernamePrincipal;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A simple file-based <tt>Realm</tt> that can be used to implement role-based and permission-based security with
 * a users, roles, and permissions defined in a properties file.
 *
 * <p>The .properties file format understood by this implementation must be written in as follows:
 *
 * <p>Each line's key/value pair represents either a user-to-role(s) mapping <em>or</em> a role-to-permission(s)
 * mapping.
 *
 * <p>The user-to-role(s) lines have this format:</p>
 *
 * <p><code><b>user.</b><em>username1</em> = <em>password1</em>,role1,role2,...</code></p>
 *
 * <p>Note that each key is prefixed with the token <tt><b>user.</b></tt>  Each value must specify that user's
 * password followed by zero or more role names assigned to that user.</p>
 *
 * <p>The role-to-permission(s) lines have this format:</p>
 *
 * <p><code><b>role.</b><em>rolename1</em> = <em>permissionDefinition1</em>;<em>permissionDefinition2</em>;...</code></p>
 *
 * <p>where each key is prefixed with the token <tt><b>role.</b></tt> and the value is one or more
 * <em>permissionDefinition</em>s.  A <em>permissionDefinition</em> is defined as</p>
 *
 * <p><code><em>permissionClassName</em>,<em>permissionName</em>,<em>optionalActionsString</em></code></p>
 *
 * <p>corresponding to the associated class attributes of a
 * {@link org.jsecurity.authz.Permission Permission} or
 * {@link org.jsecurity.authz.TargetedPermission TargetedPermission}.
 * <em>optionalActionsString</em> is optional, but if it exists, it <em>is</em> allowed to contain commas as well.
 * But note that because <em>permissionDefinition</em> is internally delimited via commas (,), multiple
 * <em>permissionDefinition</em>s for a single role must be delimited via semi-colons (;)
 *
 * <p>Here is an example of a very simple properties file that conforms to the above format rules:
 *
 * <code><pre>user.root = administrator
user.jsmith = manager,engineer,employee
user.abrown = qa,employee
user.djones = qa,contractor

role.administrator = org.jsecurity.authz.support.AllPermission
role.manager = com.domain.UserPermission,*,read,write;com.domain.FilePermission,/usr/local/emailManagers.sh,execute
role.engineer = com.domain.FilePermission,/usr/local/tomcat/bin/startup.sh,read,execute
role.employee = com.domain.IntranetPermission,useWiki
role.qa = com.domain.QAServerPermission,*,view,start,shutdown,restart;com.domain.ProductionServerPermission,*,view
role.contractor = com.domain.IntranetPermission,useTimesheet</pre></code>
 *
 * @author Jeremy Haile
 * @since 0.2
 */
public class PropertyFileRealm extends AuthenticatingRealm implements Runnable, Initializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final int DEFAULT_RELOAD_INTERVAL_SECONDS = 10;
    private static final String USERNAME_PREFIX = "user.";
    private static final String ROLENAME_PREFIX = "role.";
    private static final String USER_ROLENAME_DELIMITER = ",";
    private static final String DEFAULT_FILE_PATH = "users.properties";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog( getClass() );

    protected boolean useXmlFormat = false;

    protected String filePath = DEFAULT_FILE_PATH;

    protected long fileLastModified;

    protected int reloadIntervalSeconds = DEFAULT_RELOAD_INTERVAL_SECONDS;

    protected Map<String,SimpleUser> userMap = new HashMap<String, SimpleUser>();
    protected Map<String,SimpleRole> roleMap = new HashMap<String,SimpleRole>();

    public PropertyFileRealm() {
    }

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public void init() {
        reloadProperties();
        startReloadThread();
    }

    protected void startReloadThread() {
        if ( this.reloadIntervalSeconds > 0 ) {
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
            scheduler.scheduleAtFixedRate( this, reloadIntervalSeconds, reloadIntervalSeconds, TimeUnit.SECONDS );
        }
    }

    public void run() {
        try {
            reloadPropertiesIfNecessary();
        } catch ( Exception e ) {
            if ( log.isErrorEnabled() ) {
                log.error( "Error while reloading property files for realm.", e );
            }
        }
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * todo javadoc
     * @param useXmlFormat
     */
    public void setUseXmlFormat(boolean useXmlFormat) {
        this.useXmlFormat = useXmlFormat;
    }

    /**
     * todo Document file path conventions (classpath:, file:, url:, etc.)
     * @param filePath
     */
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    /**
     * todo javadoc
     * @param reloadIntervalSeconds
     */
    public void setReloadIntervalSeconds(int reloadIntervalSeconds) {
        this.reloadIntervalSeconds = reloadIntervalSeconds;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    private void reloadPropertiesIfNecessary() {
        if ( haveFilesBeenModified() ) {
            reloadProperties();
        }
    }

    private boolean haveFilesBeenModified() {
        File propertyFile = new File( this.filePath);
        long currentLastModified = propertyFile.lastModified();

        if ( currentLastModified > this.fileLastModified) {
            this.fileLastModified = currentLastModified;
            return true;
        } else {
            return false;
        }
    }

    @SuppressWarnings( "unchecked" )
    private void reloadProperties() {

        if ( filePath == null || filePath.length() == 0 ) {
            throw new IllegalStateException( "The filePath property is not set.  " +
                "It must be set prior to this realm being initialized." );
        }

        if ( logger.isDebugEnabled() ) {
            logger.debug( "Loading user security information from file [" + filePath + "]..." );
        }

        Properties properties = loadProperties(filePath);
        createRealmEntitiesFromProperties( properties );
    }


    protected String getName( String key, String prefix ) {
        return key.substring( 0, prefix.length() );
    }

    protected String getUsername( String key ) {
        return getName( key, USERNAME_PREFIX );
    }

    protected String getRolename( String key ) {
        return getName( key, ROLENAME_PREFIX );
    }

    protected boolean isUsername( String key ) {
        return key != null && key.startsWith( USERNAME_PREFIX );
    }

    protected boolean isRolename( String key ) {
        return key != null && key.startsWith( ROLENAME_PREFIX );
    }

    protected static Set<String> toSet( String delimited, String delimiter ) {
        if ( delimited == null || delimited.trim().equals( "" ) ) {
            return null;
        }

        Set<String> values = new HashSet<String>();
        String[] rolenamesArray = delimited.split( delimiter );
        for( String s : rolenamesArray ) {
            String trimmed = s.trim();
            if ( trimmed.length() > 0 ) {
                values.add( trimmed );
            }
       }

       return values;
    }


    @SuppressWarnings( "unchecked" )
    private void createRealmEntitiesFromProperties( Properties userProperties ) {

        Map<String,SimpleUser> userMap = new HashMap<String,SimpleUser>();
        Map<String,SimpleRole> roleMap = new HashMap<String,SimpleRole>();

        Enumeration<String> propNames = (Enumeration<String>)userProperties.propertyNames();

        while ( propNames.hasMoreElements() ) {

            String key = propNames.nextElement();
            String value = userProperties.getProperty( key );

            if ( isUsername( key ) ) {
                String username = getUsername( key );

                String[] passwordAndRolesArray = value.split( USER_ROLENAME_DELIMITER, 2 );
                String password = passwordAndRolesArray[0];

                SimpleUser user = userMap.get( username );
                if ( user == null ) {
                    user = new SimpleUser( username, password );
                    userMap.put( username, user );
                }
                user.setPassword( password );

                Set<String> valueRolenames;
                if ( passwordAndRolesArray.length > 1 ) {
                    valueRolenames = toSet( passwordAndRolesArray[1], USER_ROLENAME_DELIMITER );
                    if ( valueRolenames != null && !valueRolenames.isEmpty() ) {
                        for( String rolename : valueRolenames ) {
                            SimpleRole role = roleMap.get( rolename );
                            if ( role == null ) {
                                role = new SimpleRole( rolename );
                                roleMap.put( rolename, role );
                            }
                            user.add( role );
                        }
                    } else {
                        user.setRoles( null );
                    }
                } else {
                    user.setRoles( null );
                }
            } else if ( isRolename( key ) ) {

                String rolename = getRolename( key );

                SimpleRole role = roleMap.get( rolename );
                if ( role == null ) {
                    role = new SimpleRole( rolename );
                    roleMap.put( rolename, role );
                }

                Set<Permission> permissions = PermissionUtils.createPermissions( value );
                role.setPermissions( permissions );
            } else {
                String msg = "Encountered unexpected key/value pair.  All keys must be prefixed with either '" + 
                    USERNAME_PREFIX + "' or '" + ROLENAME_PREFIX + "'.";
                throw new IllegalStateException( msg );
            }
        }

        this.userMap = userMap;
        this.roleMap = roleMap;
    }

    private Properties loadProperties( String filePath ) {
        Properties props = new Properties();

        InputStream is = null;
        try {

            if( logger.isDebugEnabled() ) {
               logger.debug( "Opening input stream for file path [" + filePath + "]..." );
            }

            is = ResourceUtils.getInputStreamForPath( filePath );
            if ( useXmlFormat ) {

                if ( logger.isDebugEnabled() ) {
                    logger.debug( "Loading properties from path [" + filePath + "] in XML format..." );
                }

                props.loadFromXML( is );
            } else {

                if ( logger.isDebugEnabled() ) {
                    logger.debug( "Loading properties from path [" + filePath + "]..." );
                }

                props.load( is );
            }

        } catch ( IOException e ) {
            throw new JSecurityException( "Error reading properties path [" + filePath + "].  " +
                "Initializing of the realm from this file failed.", e );
        } finally {
            ResourceUtils.close( is );
        }

        return props;
    }


    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;

        SimpleUser user = userMap.get( upToken.getUsername() );
        if( user == null ) {
            return null;
        }

        Principal principal = new UsernamePrincipal( user.getUsername() );

        return new SimpleAuthenticationInfo( principal, user.getPassword() );

    }

    protected String getUsername( Principal principal ) {
        if ( principal instanceof UsernamePrincipal ) {
            return ((UsernamePrincipal)principal).getUsername();
        } else {
            String msg = "The " + getClass().getName() + " implementation expects all Principal arguments to be " +
                "instances of the [" + UsernamePrincipal.class.getName() + "] class";
            throw new IllegalArgumentException( msg );
        }
    }

    protected SimpleUser getUser( Principal principal ) {
        return this.userMap.get( getUsername( principal ) );
    }

    public boolean hasRole(Principal principal, String roleIdentifier ) {
        SimpleUser user = getUser( principal );
        return ( user != null && user.hasRole( roleIdentifier ) );
    }


    public boolean[] hasRoles(Principal principal, List<String> roleIdentifiers) {
        boolean[] hasRoles = new boolean[roleIdentifiers.size()];
        for( int i = 0; i < roleIdentifiers.size(); i++ ) {
            hasRoles[i] = hasRole( principal, roleIdentifiers.get(i) );
        }
        return hasRoles;
    }

    public boolean hasAllRoles(Principal principal, Collection<String> roleIdentifiers) {
        for( String rolename : roleIdentifiers ) {
            if( !hasRole( principal, rolename ) ) {
                return false;
            }
        }
        return true;
    }

    public boolean isPermitted(Principal principal, Permission permission) {
        SimpleUser user = getUser( principal );
        return user != null && user.isPermitted( permission );
    }

    public boolean[] isPermitted(Principal principal, List<Permission> permissions) {
        boolean[] permitted = new boolean[permissions.size()];
        for( int i = 0; i < permissions.size(); i++ ) {
            permitted[i] = isPermitted( principal, permissions.get(i) );
        }
        return permitted;
    }

    public boolean isPermittedAll(Principal principal, Collection<Permission> permissions) {
        for( Permission perm : permissions ) {
            if ( !isPermitted( principal, perm ) ) {
                return false;
            }
        }
        return true;
    }

    public void checkPermission(Principal principal, Permission permission) throws AuthorizationException {
        if ( !isPermitted( principal, permission ) ) {
            throw new UnauthorizedException( "User does not have permission [" + permission + "]" );
        }
    }

    public void checkPermissions(Principal principal, Collection<Permission> permissions) throws AuthorizationException {
        if( permissions != null ) {
            for( Permission permission : permissions ) {
                if( !isPermitted( principal, permission ) ) {
                   throw new UnauthorizedException( "User does not have permission [" + permission + "]" );
                }
            }
        }
    }

    public void checkRole(Principal principal, String role) throws AuthorizationException {
        if ( !hasRole( principal, role ) ) {
            throw new UnauthorizedException( "User does not have role [" + role + "]" );
        }
    }

    public void checkRoles(Principal principal, Collection<String> roles) throws AuthorizationException {
        if ( roles != null ) {
            for( String role : roles ) {
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
        return true;
    }

    public boolean isAuthorized( Principal subjectIdentifier, AuthorizedAction action ) {
        return true;
    }

    public void checkAuthorization( Principal subjectIdentifier, AuthorizedAction action ) throws AuthorizationException {
        //does nothing
    }


}