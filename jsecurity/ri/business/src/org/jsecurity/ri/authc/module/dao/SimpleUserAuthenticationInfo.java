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

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;

/**
 * Simple implementation of the {@link UserAuthenticationInfo} interface that
 * contains all necessary information as instance variables and exposes them
 * via getters and setters using standard JavaBean notation.
 *
 * @see UserAuthenticationInfo
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SimpleUserAuthenticationInfo implements UserAuthenticationInfo {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * User's username.
     */
    private String username;

    /**
     * User's password - this should be encrypted if the password is stored
     * in an encrypted form (which is of course recommended)
     */
    private char[] password;

    /**
     * The collection of roles that apply to this user.
     */
    private Collection<Serializable> roles;

    /**
     * True if the user's account is locked, false otherwise.
     */
    private boolean accountLocked = false;

    /**
     * True if the user's credentials are expired, false otherwise.
     */
    private boolean credentialsExpired = false;

    /**
     * True if the user is allowed to log in concurrently from two
     * separate locations, false otherwise.
     */
    private boolean concurrentLoginsAllowed = true;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SimpleUserAuthenticationInfo() {
        this.roles = new HashSet<Serializable>();
    }


    public SimpleUserAuthenticationInfo(String username, char[] password, Collection<Serializable> roles) {
        this.username = username;
        this.password = password;
        this.roles = roles;
    }


    public SimpleUserAuthenticationInfo(String username, char[] password, Collection<Serializable> roles, boolean accountLocked, boolean credentialsExpired, boolean concurrentLoginsAllowed) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.accountLocked = accountLocked;
        this.credentialsExpired = credentialsExpired;
        this.concurrentLoginsAllowed = concurrentLoginsAllowed;
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


    public char[] getPassword() {
        return password;
    }


    public void setPassword(char[] password) {
        this.password = password;
    }


    public Collection<Serializable> getRoles() {
        return roles;
    }


    public void setRoles(Collection<Serializable> roles) {
        this.roles = roles;
    }


    public boolean isAccountLocked() {
        return accountLocked;
    }


    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }


    public boolean isCredentialsExpired() {
        return credentialsExpired;
    }


    public void setCredentialsExpired(boolean credentialsExpired) {
        this.credentialsExpired = credentialsExpired;
    }


    public boolean isConcurrentLoginsAllowed() {
        return concurrentLoginsAllowed;
    }


    public void setConcurrentLoginsAllowed(boolean concurrentLoginsAllowed) {
        this.concurrentLoginsAllowed = concurrentLoginsAllowed;
    }


    /*--------------------------------------------
    |               M E T H O D S               |
    ============================================*/

}