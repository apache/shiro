/*
 * Copyright (C) 2005 Jeremy C. Haile, Les A. Hazlewood
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

import java.security.Principal;

/**
 * <p>A simple username/password authentication token.  This class is included in the API
 * since it is a very widely used authentication mechanism.</p>
 *
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class UsernamePasswordToken implements AuthenticationToken, java.io.Serializable {

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

    /**
     * JavaBeans compatible no-arg constructor.
     */
    public UsernamePasswordToken(){}

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted
     * during an authentication attempt.
     *
     * <p>This is a convience constructor and maintains the password internally via a character
     * array, i.e. <tt>password.toCharArray();</tt>
     *
     * @param username the username submitted for authentication
     * @param password the password string submitted for authentication
     */
    public UsernamePasswordToken(final String username, final String password ) {
        this.username = username;
        this.password = password.toCharArray();
    }

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted
     * during an authentication attempt.
     * @param username the username submitted for authentication
     * @param password the password character array submitted for authentication
     */
    public UsernamePasswordToken(final String username, final char[] password) {
        this.username = username;
        this.password = password;
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    /**
     * Returns the username submitted during an authentication attempt.
     * @return the username submitted during an authentication attempt.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username for submission during an authentication attempt.
     * @param username the username to be used for submission during an authentication attempt.
     */
    public void setUsername( String username ) {
        this.username = username;
    }


    /**
     * Returns the password submitted during an authentication attempt as a character array.
     * @return the password submitted during an authentication attempt as a character array.
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Sets the password for submission during an authentication attempt.
     * @param password  the password to be used for submission during an authentication attemp.
     */
    public void setPassword( char[] password ) {
        this.password = password;
    }

    /**
     * Returns the {@link #getUsername() username} as a Principal.
     * @see org.jsecurity.authc.AuthenticationToken#getPrincipal()
     * @return the {@link #getUsername() username} as a Principal.
     */
    public Principal getPrincipal() {
        final String username = getUsername();
        return new Principal() {
            public int hashCode() {
                return username.hashCode();
            }

            public boolean equals( Object obj ) {
                return getName().equals( username );
            }

            public String toString() {
                return username;
            }

            public String getName() {
                return username;
            }
        };
    }

    /**
     * Returns the {@link #getPassword() password} char array.
     * @see org.jsecurity.authc.AuthenticationToken#getCredentials()
     * @return the {@link #getPassword() password} char array.
     */
    public Object getCredentials() {
        return getPassword();
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Clears out (nulls) the username and password.  The password bytes are explicitly set to
     * <tt>0x00</tt> before nulling to eliminate the possibility of memory access at a later time.
     */
    public void clear() {
        this.username = null;

        if( this.password != null ) {
            for( int i = 0; i < password.length; i++ ) {
                this.password[i] = 0x00;
            }
            this.password = null;
        }

    }

    /**
     * Returns the String representation.  It does not include the password in the resulting
     * string for security reasons to prevent accidentially printing out a password
     * that might be widely viewable).
     *
     * @return the String representation of the <tt>UsernamePasswordToken</tt>, omitting
     * the password.
     */
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append( getClass().getName() );
        sb.append( " - " );
        sb.append( username );
        return sb.toString();
    }

}