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

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationInfo;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.realm.support.AbstractCachingRealm;
import org.jsecurity.realm.support.AuthorizationInfo;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Properties;

/**
 * A simple file-based <tt>Realm</tt> that can be used to implement role-based security with
 * a set of users defined in a properties file.
 *
 * TODO THIS IS A WORK IN PROGRESS - LES, IM NOT DONE.
 * @since 0.2
 * @author Jeremy Haile
 */
public class PropertyFilesRealm extends AbstractCachingRealm {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private boolean useXmlFormat = false;

    private String userFile;

    private String permissionsFile;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void onInit() {
        loadProperties();
    }

    private void loadProperties() {
        Properties props = new Properties();
        try {

            InputStream userStream = new FileInputStream( userFile );

            if( useXmlFormat ) {
                props.loadFromXML( userStream );
            } else {
                props.load( userStream );
            }
        } catch( IOException e ) {
            //todo throw exception here
        }
    }

    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {




        return null;
    }

    protected AuthorizationInfo doGetAuthorizationInfo(Principal principal) {
        return null;
    }

}