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

package org.jsecurity.authc;

/**
 * <p>A simple username password authentication token.  This class is included in the API
 * since it is a very widely used authentication mechanism.</p>
 *
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class UsernamePasswordToken implements AuthenticationToken {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private String username;

    private char[] password;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public UsernamePasswordToken(final String username, final String password ) {
        this.username = username;
        this.password = password.toCharArray();
    }

    public UsernamePasswordToken(final String username, final char[] password) {
        this.username = username;
        this.password = password;
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/
    public String getUsername() {
        return username;
    }


    public char[] getPassword() {
        return password;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/
    public void clear() {
        this.username = null;

        if( this.password != null ) {
            for( int i = 0; i < password.length; i++ ) {
                this.password[i] = 0x00;
            }
            this.password = null;
        }

    }
}