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

package org.jsecurity.realm.support.file;

import org.jsecurity.JSecurityException;
import org.jsecurity.realm.support.memory.MemoryRealm;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.ResourceUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.Properties;
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
 * TODO - clean up this JavaDoc in relation to the MemorRealm JavaDoc
 * @since 0.2
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class PropertiesFileRealm extends MemoryRealm implements Runnable, Initializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final int DEFAULT_RELOAD_INTERVAL_SECONDS = 10;
    private static final String USERNAME_PREFIX = "user.";
    private static final String ROLENAME_PREFIX = "role.";
    private static final String DEFAULT_FILE_PATH = "users.properties";

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    protected boolean useXmlFormat = false;
    protected String filePath = DEFAULT_FILE_PATH;
    protected long fileLastModified;
    protected int reloadIntervalSeconds = DEFAULT_RELOAD_INTERVAL_SECONDS;

    public PropertiesFileRealm() {
    }

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public void init() {
        reloadProperties();
        super.init();
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

        if ( log.isDebugEnabled() ) {
            log.debug( "Loading user security information from file [" + filePath + "]..." );
        }

        Properties properties = loadProperties(filePath);
        createRealmEntitiesFromProperties( properties );
    }


    protected String getName( String key, String prefix ) {
        return key.substring( prefix.length(), key.length() );
    }

    protected boolean isUsername( String key ) {
        return key != null && key.startsWith( USERNAME_PREFIX );
    }

    protected boolean isRolename( String key ) {
        return key != null && key.startsWith( ROLENAME_PREFIX );
    }

    protected String getUsername( String key ) {
        return getName( key, USERNAME_PREFIX );
    }

    protected String getRolename( String key ) {
        return getName( key, ROLENAME_PREFIX );
    }

    @SuppressWarnings( "unchecked" )
    private void createRealmEntitiesFromProperties( Properties properties ) {

        Properties userProps = new Properties();
        Properties roleProps = new Properties();

        //split into respective props for parent class:

        Enumeration<String> propNames = (Enumeration<String>)properties.propertyNames();

        while ( propNames.hasMoreElements() ) {

            String key = propNames.nextElement();
            String value = properties.getProperty( key );

            if ( isUsername( key ) ) {
                String username = getUsername( key );
                userProps.put( username, value );
            } else if ( isRolename( key ) ) {
                String rolename = getRolename( key );
                roleProps.put( rolename, value );
            } else {
                String msg = "Encountered unexpected key/value pair.  All keys must be prefixed with either '" + 
                    USERNAME_PREFIX + "' or '" + ROLENAME_PREFIX + "'.";
                throw new IllegalStateException( msg );
            }
        }

        if ( !userProps.isEmpty() ) {
            setUserProperties( userProps );
        }
        if ( !roleProps.isEmpty() ) {
            setRoleProperties( roleProps );
        }
    }

    private Properties loadProperties( String filePath ) {
        Properties props = new Properties();

        InputStream is = null;
        try {

            if( log.isDebugEnabled() ) {
               log.debug( "Opening input stream for file path [" + filePath + "]..." );
            }

            is = ResourceUtils.getInputStreamForPath( filePath );
            if ( useXmlFormat ) {

                if ( log.isDebugEnabled() ) {
                    log.debug( "Loading properties from path [" + filePath + "] in XML format..." );
                }

                props.loadFromXML( is );
            } else {

                if ( log.isDebugEnabled() ) {
                    log.debug( "Loading properties from path [" + filePath + "]..." );
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

}