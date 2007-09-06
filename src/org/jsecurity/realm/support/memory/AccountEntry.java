/*
 * Copyright (C) 2005-2007 Jeremy C. Haile
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

import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * A simple POJO containing account information.
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class AccountEntry {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The username for this account.
     */
    private String username;

    /**
     * The password for this account.
     */
    private String password;


    private Set<String> roles;


    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public AccountEntry() {
    }


    public AccountEntry(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public AccountEntry(String username, String password, String rolenames) {
        this( username, password, toSet( rolenames, "," ) );
    }

    public AccountEntry( String username, String password, Set<String> rolenames ) {
        this.username = username;
        this.password = password;
        this.roles = rolenames;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public String getUsername() {
        return username;
    }


    public void setUsername(String username) {
        this.username = username;
    }


    public String getPassword() {
        return password;
    }


    public void setPassword(String password) {
        this.password = password;
    }


    public Set<String> getRoles() {
        return roles;
    }


    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public void setRoles( String rolesString ) {
        if ( rolesString != null && !"".equals( rolesString.trim() ) ) {
            setRoles( toSet( rolesString, "," ) );
        }
    }

    protected static Set<String> toSet( String delimited, String delimiter ) {
        Set<String> values = null;

        if ( delimited != null && !"".equals( delimited.trim() ) ) {
            values = new HashSet<String>();
            String[] rolenamesArray = delimited.split( delimiter );
            for( String s : rolenamesArray ) {
                String trimmed = s.trim();
                if ( !trimmed.equals( "" ) ) {
                    values.add( trimmed );
                }
            }
        }

        return values;
    }

    protected static String toDelimitedString( Collection<String> values, String delimiter ) {
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


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
}