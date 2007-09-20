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
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A subclass of <tt>MemoryRealm</tt> that defers all logic to the parent class, but just enables
 * {@link java.util.Properties Properties} based configuration in addition to the parent class's String and Map
 * configuration.
 *
 * <p>This class allows processing of a single Properties instance (or .properties file) for user, role, and
 * permission configuration.  The Properties format understood by this implementation must be written in as follows:
 *
 * <p>Each line's key/value pair represents either a user-to-role(s) mapping <em>or</em> a role-to-permission(s)
 * mapping.
 *
 * <p>The user-to-role(s) lines have this format:</p>
 *
 * <p><code><b>user.</b><em>username</em> = <em>password</em>,role1,role2,...</code></p>
 *
 * <p>Note that each key is prefixed with the token <tt><b>user.</b></tt>  Each value must adhere to the
 * the {@link #setUserDefinitions(Map) setUserDefinitions(Map)} JavaDoc.</p>
 *
 * <p>The role-to-permission(s) lines have this format:</p>
 *
 * <p><code><b>role.</b><em>rolename</em> = <em>permissionDefinition1</em>;<em>permissionDefinition2</em>;...</code></p>
 *
 * <p>where each key is prefixed with the token <tt><b>role.</b></tt> and the value adheres to the format specified in
 * the {@link #setRoleDefinitions(Map) setRoleDefinitions(Map)} JavaDoc.
 *
 * <p>Here is an example of a very simple properties definition that conforms to the above format rules and corresponding
 * method JavaDocs:
 *
 * <code><pre>   user.root = administrator
 * user.jsmith = manager,engineer,employee
 * user.abrown = qa,employee
 * user.djones = qa,contractor
 *
 * role.administrator = org.jsecurity.authz.support.AllPermission
 * role.manager = com.domain.UserPermission,*,read,write;com.domain.FilePermission,/usr/local/emailManagers.sh,execute
 * role.engineer = com.domain.FilePermission,/usr/local/tomcat/bin/startup.sh,read,execute
 * role.employee = com.domain.IntranetPermission,useWiki
 * role.qa = com.domain.QAServerPermission,*,view,start,shutdown,restart;com.domain.ProductionServerPermission,*,view
 * role.contractor = com.domain.IntranetPermission,useTimesheet</pre></code>
 *
 * @since 0.2
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class PropertiesRealm extends MemoryRealm implements Runnable, Initializable {

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

    public PropertiesRealm() {
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
     * Determines whether or not the properties XML format should be used.  For more information, see
     * {@link Properties#loadFromXML(java.io.InputStream)}
     * @param useXmlFormat true to use XML or false to use the normal format.  Defaults to false.
     */
    public void setUseXmlFormat(boolean useXmlFormat) {
        this.useXmlFormat = useXmlFormat;
    }

    /**
     * Sets the path of the properties file to load user, role, and permission information from.  The properties
     * file will be loaded using {@link ResourceUtils#getInputStreamForPath(String)} so any convention recongized
     * by that method is accepted here.  For example, to load a file from the classpath use
     * <tt>classpath:myfile.properties</tt>; to load a file from disk simply specify the full path; to load
     * a file from a URL use <tt>url:www.mysite.com/myfile.properties</tt>.
     * @param filePath the path to load the properties file from.  This is a required property.
     */
    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    /**
     * Sets the interval in seconds at which the property file will be checked for changes and reloaded.  If this is
     * set to zero or less, property file reloading will be disabled.  If it is set to 1 or greater, then a
     * separate thread will be created to monitor the propery file for changes and reload the file if it is updated.
     * @param reloadIntervalSeconds the interval in seconds at which the property file should be examined for changes.
     * If set to zero or less, reloading is disabled.
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
        try {
            super.destroy();
        } catch ( Exception e ) {
            //ignored
        }
        createRealmEntitiesFromProperties( properties );
        super.init();
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

        Map<String,String> userDefs = new HashMap<String,String>();
        Map<String,String> roleDefs = new HashMap<String,String>();

        //split into respective props for parent class:

        Enumeration<String> propNames = (Enumeration<String>)properties.propertyNames();

        while ( propNames.hasMoreElements() ) {

            String key = propNames.nextElement();
            String value = properties.getProperty( key );

            if ( isUsername( key ) ) {
                String username = getUsername( key );
                userDefs.put( username, value );
            } else if ( isRolename( key ) ) {
                String rolename = getRolename( key );
                roleDefs.put( rolename, value );
            } else {
                String msg = "Encountered unexpected key/value pair.  All keys must be prefixed with either '" + 
                    USERNAME_PREFIX + "' or '" + ROLENAME_PREFIX + "'.";
                throw new IllegalStateException( msg );
            }
        }

        setUserDefinitions( userDefs );
        setRoleDefinitions( roleDefs );

        processUserDefinitions();
        processRoleDefinitions();
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