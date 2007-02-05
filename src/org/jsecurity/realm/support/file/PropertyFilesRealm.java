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

import org.jsecurity.JSecurityException;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.support.AbstractRealm;
import org.jsecurity.realm.support.AuthorizationInfo;
import org.jsecurity.realm.support.memory.AccountEntry;
import org.jsecurity.realm.support.memory.MemoryRealm;

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
 * A simple file-based <tt>Realm</tt> that can be used to implement role-based security with
 * a set of users defined in a properties file.
 *
 * TODO THIS IS A WORK IN PROGRESS - LES, IM NOT DONE.
 * @since 0.2
 * @author Jeremy Haile
 */
public class PropertyFilesRealm extends AbstractRealm implements Runnable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    private static final int DEFAULT_RELOAD_INTERVAL_SECONDS = 10;

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
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
        if( this.reloadIntervalSeconds > 0 ) {
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
            scheduler.scheduleAtFixedRate( this, reloadIntervalSeconds, reloadIntervalSeconds, TimeUnit.SECONDS );
        }
    }

    public void run() {
        try {
            reloadPropertiesIfNecessary();

        } catch (Exception e) {
            if( log.isErrorEnabled() ) {
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
        if( haveFilesBeenModified() ) {
            reloadProperties();
        }

    }

    private boolean haveFilesBeenModified() {
        File userFile = new File( this.userFilePath );
        long newUserFileLastModified = userFile.lastModified();

        if( newUserFileLastModified > this.userFileLastModified ) {
            this.userFileLastModified = newUserFileLastModified;
            return true;
        }

        File permissionsFile = new File( this.permissionsFilePath );
        long newPermissionsFileLastModified = permissionsFile.lastModified();

        if( newPermissionsFileLastModified > this.permissionsFileLastModified ) {
            this.permissionsFileLastModified = newPermissionsFileLastModified;
            return true;
        }

        return false;
    }

    @SuppressWarnings( "unchecked" )
    private void reloadProperties() {
        MemoryRealm newRealm = new MemoryRealm();

        //todo throw exception if user file path isn't set
        Properties userProperties = loadProperties( userFilePath );
        Set<AccountEntry> entries = buildAccountEntriesFromProperties(userProperties);
        newRealm.setAccounts( entries );

        // Load permissions if enabled
        if( permissionsFilePath != null && permissionsFilePath.length() > 0 ) {
            //todo add debug output here and in else block
            Properties permissionProperties = loadProperties( permissionsFilePath );
            Map<String,String> rolesPermissionsMap = buildRolesPermissionsMapFromProperties( permissionProperties );
            newRealm.setRolesPermissionsMap( rolesPermissionsMap );
        }

        // Initialize new realm and replace old realm
        newRealm.init();
        this.memoryRealm = newRealm;
    }

    private Set<AccountEntry> buildAccountEntriesFromProperties(Properties userProperties) {
        Enumeration<String> propNames = (Enumeration<String>) userProperties.propertyNames();
        Set<AccountEntry> entries = new HashSet<AccountEntry>( userProperties.size() );
        while( propNames.hasMoreElements() ) {

            //todo validate this input
            String username = propNames.nextElement();
            String passwordRoles = userProperties.getProperty( username );

            String[] passwordRolesArray = passwordRoles.split( ",", 2 );
            String password = passwordRolesArray[0];
            String roles = passwordRolesArray[1];

            AccountEntry entry = new AccountEntry();
            entry.setUsername( username );
            entry.setPassword( password );

            if( roles != null && roles.length() > 0 ) {
                entry.setRoles( roles );
            }

            entries.add( entry );
        }
        return entries;
    }

    private Map<String, String> buildRolesPermissionsMapFromProperties(Properties permissionProperties) {
        
        return null;
    }

    private Properties loadProperties( String fileName ) {
        Properties props = new Properties();
        try {

            InputStream is = new FileInputStream( fileName );
            if( useXmlFormat ) {
                props.loadFromXML( is );
            } else {
                props.load( is );
            }

        } catch( IOException e ) {
            throw new JSecurityException( "Error reading properties file [" + fileName + "].  " +
                    "Initializing of the realm from this file failed.", e );
        }

        return props;
    }

    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {

        // Check to make sure files haven't changed
        reloadPropertiesIfNecessary();



        return null;
    }

    protected AuthorizationInfo getAuthorizationInfo(Principal principal) {

        // Check to make sure files haven't changed
        reloadPropertiesIfNecessary();

        return null;
    }


}