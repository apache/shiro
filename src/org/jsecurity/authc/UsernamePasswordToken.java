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
package org.jsecurity.authc;

import java.net.InetAddress;

/**
 * <p>A simple username/password authentication token to support the most widely-used authentication mechanism.  This
 * class also implements the <tt>InetAuthenticationToken</tt> interface to retain the IP address location from where
 * the authentication attempt is occuring, in case this information is desireable for an application.</p>
 *
 * <p>Note that this class stores a password as a char[] instead of a String
 * (which may seem more logical).  This is because Strings are immutable and their
 * internal value cannot be overwritten.  For more information, see the
 * <a href="http://java.sun.com/j2se/1.5.0/docs/guide/security/jce/JCERefGuide.html#PBEEx">
 * Java Cryptography Extension Reference Guide</a>.</p>
 *
 * <p>The contents of this token should be cleared after the authentication attempt by calling the
 * {@link #clear()} method.</p>
 * 
 * @since 0.1
 * @author Jeremy Haile
 * @author Les Hazlewood
 */
public class UsernamePasswordToken implements InetAuthenticationToken, java.io.Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    private String username;

    private char[] password;

    private InetAddress inetAddress;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/

    /**
     * JavaBeans compatible no-arg constructor.
     */
    public UsernamePasswordToken(){}

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted
     * during an authentication attempt, with a <tt>null</tt> {@link #getInetAddress() inetAddress}.
     * @param username the username submitted for authentication
     * @param password the password character array submitted for authentication
     */
    public UsernamePasswordToken(final String username, final char[] password) {
        this( username, password, null );
    }

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted
     * during an authentication attempt, with a <tt>null</tt> {@link #getInetAddress() inetAddress}
     *
     * <p>This is a convience constructor and maintains the password internally via a character
     * array, i.e. <tt>password.toCharArray();</tt>.  Note that storing a password as a String
     * in your code could have possible security implications as noted in the class JavaDoc.</p>
     *
     * @param username the username submitted for authentication
     * @param password the password string submitted for authentication
     */
    public UsernamePasswordToken(final String username, final String password ) {
        this( username, password.toCharArray(), null );
    }

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted, as well as the
     * inetAddress from where the attempt is occurring.
     *
     * @param username the username submitted for authentication
     * @param password the password string submitted for authentication
     * @param inetAddress the inetAddress from where the attempt is occuring
     *
     * @since 0.2
     */
    public UsernamePasswordToken(final String username, final char[] password, final InetAddress inetAddress ) {
        this.username = username;
        this.password = password;
        this.inetAddress = inetAddress;
    }

    /**
     * Constructs a new UsernamePasswordToken encapsulating the username and password submitted, as well as the
     * inetAddress from where the attempt is occurring.
     *
     * <p>This is a convience constructor and maintains the password internally via a character
     * array, i.e. <tt>password.toCharArray();</tt>.  Note that storing a password as a String
     * in your code could have possible security implications as noted in the class JavaDoc.</p>
     *
     * @param username the username submitted for authentication
     * @param password the password string submitted for authentication
     * @param inetAddress the inetAddress from where the attempt is occuring
     *
     * @since 0.2
     */
    public UsernamePasswordToken( final String username, final String password, final InetAddress inetAddress ) {
        this( username, password.toCharArray(), inetAddress );
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
    public Object getPrincipal() {
        return getUsername();
    }

    /**
     * Returns the {@link #getPassword() password} char array.
     * @see org.jsecurity.authc.AuthenticationToken#getCredentials()
     * @return the {@link #getPassword() password} char array.
     */
    public Object getCredentials() {
        return getPassword();
    }

    /**
     * Returns the inetAddress from where the authentication attempt occurs.  May be <tt>null</tt> if the inetAddress
     * is unknown or explicitly omitted.  It is up to the Authenticator implementation processing this token if
     * an authentication attempt without an inetAddress is valid or not.
     *
     * <p>(JSecurity's default Authenticator
     * allows <tt>null</tt> IPs to support localhost and proxy server environments).</p>
     * @return the inetAddress from where the authentication attempt occurs, or <tt>null</tt> if it is unknown or 
     * explicitly omitted.
     * @since 0.2
     */
    public InetAddress getInetAddress() {
        return inetAddress;
    }

    /**
     * Sets the inetAddress from where the authentication attempt occurs.  It is up to the Authenticator
     * implementation processing this token if  an authentication attempt without an inetAddress is valid or not.
     *
     * <p>(JSecurity's default Authenticator
     * allows <tt>null</tt> IPs to support localhost and proxy server environments).</p>
     * @param inetAddress the inetAddress from where the authentication attempt occurs.
     * @since 0.2
     */
    public void setInetAddress( InetAddress inetAddress ) {
        this.inetAddress = inetAddress;
    }

    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

    /**
     * Clears out (nulls) the username and password and inetAddress.  The password bytes are explicitly set to
     * <tt>0x00</tt> before nulling to eliminate the possibility of memory access at a later time.
     */
    public void clear() {
        this.username = null;
        this.inetAddress = null;

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
        if ( inetAddress != null ) {
            sb.append( " (" ).append( inetAddress ).append( ")");
        }
        return sb.toString();
    }

}