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
import org.jsecurity.authz.Permission;
import org.jsecurity.realm.support.AbstractRealm;
import org.jsecurity.realm.support.AuthorizationInfo;
import org.jsecurity.realm.support.memory.AccountEntry;
import org.jsecurity.realm.support.memory.MemoryRealm;
import org.jsecurity.util.Initializable;

import java.io.File;
import java.io.FileInputStream;
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
public class PropertyFilesRealm extends AbstractRealm implements Runnable, Initializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final int DEFAULT_RELOAD_INTERVAL_SECONDS = 10;
    private static final String USERNAME_PREFIX = "user.";
    private static final String ROLENAME_PREFIX = "role.";
    private static final String USER_ROLENAME_DELIMITER = ",";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * Commons-logging logger
     */
    protected final transient Log logger = LogFactory.getLog( getClass() );

    protected boolean useXmlFormat = false;

    protected String userFilePath;

    protected String permissionsFilePath;

    protected long userFileLastModified;

    protected long permissionsFileLastModified;

    protected MemoryRealm memoryRealm;

    protected int reloadIntervalSeconds = DEFAULT_RELOAD_INTERVAL_SECONDS;

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

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    private void reloadPropertiesIfNecessary() {
        if ( haveFilesBeenModified() ) {
            reloadProperties();
        }

    }

    private boolean haveFilesBeenModified() {
        File userFile = new File( this.userFilePath );
        long newUserFileLastModified = userFile.lastModified();

        if ( newUserFileLastModified > this.userFileLastModified ) {
            this.userFileLastModified = newUserFileLastModified;
            return true;
        }

        File permissionsFile = new File( this.permissionsFilePath );
        long newPermissionsFileLastModified = permissionsFile.lastModified();

        if ( newPermissionsFileLastModified > this.permissionsFileLastModified ) {
            this.permissionsFileLastModified = newPermissionsFileLastModified;
            return true;
        }

        return false;
    }

    @SuppressWarnings( "unchecked" )
    private void reloadProperties() {
        MemoryRealm newRealm = new MemoryRealm();

        if ( userFilePath == null || userFilePath.length() == 0 ) {
            throw new IllegalStateException( "The userFilePath property is not set.  " +
                "It must be set prior to this realm being initialized." );
        }

        if ( logger.isDebugEnabled() ) {
            logger.debug( "Loading user account information from file [" + userFilePath + "]..." );
        }

        Properties userProperties = loadProperties( userFilePath );
        Set<AccountEntry> entries = buildAccountEntriesFromProperties( userProperties );
        newRealm.setAccounts( entries );

        // Load permissions if enabled
        if ( permissionsFilePath != null && permissionsFilePath.length() > 0 ) {

            if ( logger.isDebugEnabled() ) {
                logger.debug( "Loading permission information from file [" + permissionsFilePath + "]..." );
            }

            Properties permissionProperties = loadProperties( permissionsFilePath );
            Map<String, String> rolesPermissionsMap = buildRolesPermissionsMapFromProperties( permissionProperties );
            newRealm.setRolesPermissionsMap( rolesPermissionsMap );

        } else {
            if ( logger.isDebugEnabled() ) {
                logger.debug( "Permissions are not being loaded, because no permissionsFilePath has been configured." );
            }
        }

        // Initialize new realm and replace old realm
        newRealm.init();
        this.memoryRealm = newRealm;
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

    protected List<String> toList( String delimited, String delimiter ) {
        List<String> values = null;

        if ( delimited != null ) {
            values = new ArrayList<String>();
            String[] rolenamesArray = delimited.split( delimiter );
            for( String s : rolenamesArray ) {
                String trimmed = s.trim();
                if ( !trimmed.equals( "" ) ) {
                    values.add( trimmed );
                }
            }
        } else {
            values = Collections.EMPTY_LIST;
        }

        return values;
    }

    protected String toDelimitedString( List<String> values, String delimiter ) {
        if ( values == null || values.isEmpty() ) {
            return null;
        }
        StringBuffer sb = new StringBuffer();
        Iterator<String> i = values.iterator();
        while( i.hasNext() ) {
            sb.append( i.next() );
            if ( i.hasNext() ) {
                sb.append( delimiter );
            }
        }
        return sb.toString();
    }

    protected String getPassword( List<String> userLineValues ) {
        if ( userLineValues.isEmpty() ) {
            String msg = "A user-to-role(s) key/value pair must specify the user's password as the first token in the value.";
            throw new IllegalStateException( msg );
        }
        return userLineValues.get( 0 );
    }

    @SuppressWarnings( "unchecked" )
    private Set<AccountEntry> buildAccountEntriesFromProperties( Properties userProperties ) {

        Set<String> usernames = new HashSet<String>();
        Map<String,List<String>> userRolesMap = new HashMap<String,List<String>>();
        Set<String> rolenames = new HashSet<String>();
        Map<String, Permission> rolePermsMap = new HashMap<String,Permission>();

        Enumeration<String> propNames = (Enumeration<String>)userProperties.propertyNames();
        Set<AccountEntry> entries = new HashSet<AccountEntry>( userProperties.size() );
        while ( propNames.hasMoreElements() ) {

            String key = propNames.nextElement();

            if ( isUsername( key ) ) {
                String username = getUsername( key );
                usernames.add( username );
                String passwordAndRoles = userProperties.getProperty( key );
                String[] passwordAndRolesArray = passwordAndRoles.split( USER_ROLENAME_DELIMITER, 2 );
                String password = passwordAndRolesArray[0];
                List<String> valueRolenames = null;
                if ( passwordAndRolesArray.length > 1 ) {
                    valueRolenames = toList( passwordAndRolesArray[1], USER_ROLENAME_DELIMITER );
                    rolenames.addAll( valueRolenames );
                    userRolesMap.put( username, valueRolenames );
                }

                usernames.add( username );
                rolenames.addAll( valueRolenames );

            }

            String username = getUsername( key );






            //todo validate this input

//            String username = propNames.nextElement();
//            String passwordRoles = userProperties.getProperty( username );
//
//            String[] passwordRolesArray = passwordRoles.split( ",", 2 );
//            String password = passwordRolesArray[0];
//            String roles = passwordRolesArray[1];
//
//            AccountEntry entry = new AccountEntry();
//            entry.setUsername( username );
//            entry.setPassword( password );
//
//            if ( roles != null && roles.length() > 0 ) {
//                entry.setRoles( roles );
//            }
//
//            entries.add( entry );
        }
        return entries;
    }

    private Map<String, String> buildRolesPermissionsMapFromProperties( Properties permissionProperties ) {

        return null;
    }

    private Properties loadProperties( String fileName ) {
        Properties props = new Properties();
        try {

            InputStream is = new FileInputStream( fileName );
            if ( useXmlFormat ) {

                if ( logger.isDebugEnabled() ) {
                    logger.debug( "Loading properties from file [" + fileName + "] in XML format..." );
                }

                props.loadFromXML( is );
            } else {

                if ( logger.isDebugEnabled() ) {
                    logger.debug( "Loading properties from file [" + fileName + "]..." );
                }

                props.load( is );
            }

        } catch ( IOException e ) {
            throw new JSecurityException( "Error reading properties file [" + fileName + "].  " +
                "Initializing of the realm from this file failed.", e );
        }

        return props;
    }

    protected AuthenticationInfo doGetAuthenticationInfo( AuthenticationToken token ) throws AuthenticationException {

        return null;
    }

    protected AuthorizationInfo getAuthorizationInfo( Principal principal ) {

        return null;
    }


}