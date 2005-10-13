/*
* Copyright (C) 2005 Jeremy C. Haile
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


package org.jsecurity.ri.authc.module.dao;

import java.util.HashSet;
import java.util.Set;

/**
 * A simple implementation of the {@link AuthenticationDAO} interface that
 * uses a set of configured user properties to authenticate a user.
 * The property name corresponds to the username of the user.  The
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class InMemoryAuthenticationDAO implements AuthenticationDAO {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The set of accounts that can be authenticated using this DAO.
     */
    private Set<AccountEntry> accounts;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public void setAccounts(Set<AccountEntry> accounts) {
        this.accounts = accounts;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/


    public AuthenticationInfo getUserAuthenticationInfo(String username) {

        for( AccountEntry entry : accounts ) {
            if( entry.getUsername().equals( username ) ) {

                String[] roleArray = entry.getRoles().split( "," );
                Set<String> roles = new HashSet<String>( roleArray.length );
                for( String role : roleArray ) {
                    roles.add( role.trim() );
                }

                SimpleAuthenticationInfo info = new SimpleAuthenticationInfo( entry.getUsername(),
                                                                              entry.getPassword().toCharArray(),
                                                                              roles );
                return info;

            }
        }

        // User could not be found, so return null
        return null;
    }
}