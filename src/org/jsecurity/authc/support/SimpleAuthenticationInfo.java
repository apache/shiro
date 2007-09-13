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

package org.jsecurity.authc.support;

import org.jsecurity.authc.AuthenticationInfo;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * Simple implementation of the {@link org.jsecurity.authc.AuthenticationInfo} interface that
 * contains all necessary information as instance variables and exposes them
 * via getters and setters using standard JavaBean notation.
 *
 * @see org.jsecurity.authc.AuthenticationInfo
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SimpleAuthenticationInfo implements AuthenticationInfo, Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The principals that apply to the subject/user who has been authenticated.
     */
    private List principals;

    /**
     * Credentials that were used to authenticate the user.
     */
    private Object credentials;

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
    public SimpleAuthenticationInfo() {
        this.principals = new ArrayList<Object>();
    }

    public SimpleAuthenticationInfo( Object principal, Object credentials) {
        this();
        //noinspection unchecked
        this.principals.add( principal );
        this.credentials = credentials;
    }

    public SimpleAuthenticationInfo(List<Object> principals, Object credentials) {
        this.principals = principals;
        this.credentials = credentials;
    }

    public SimpleAuthenticationInfo(List<Object> principals, Object credentials, boolean accountLocked, boolean credentialsExpired) {
        this.principals = principals;
        this.credentials = credentials;
        this.accountLocked = accountLocked;
        this.credentialsExpired = credentialsExpired;
    }

    public SimpleAuthenticationInfo(List<Object> principals, Object credentials, boolean accountLocked, boolean credentialsExpired, boolean concurrentLoginsAllowed) {
        this.principals = principals;
        this.credentials = credentials;
        this.accountLocked = accountLocked;
        this.credentialsExpired = credentialsExpired;
        this.concurrentLoginsAllowed = concurrentLoginsAllowed;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public Object getPrincipal() {
        if( this.principals == null ) {
            return null;
        } else {
            return this.principals.get(0);
        }
    }

    public List getPrincipals() {
        return principals;
    }

    public void setPrincipals(List<Object> principals) {
        this.principals = principals;
    }

    public void addPrincipal( Object principal ) {
        //noinspection unchecked
        this.principals.add( principal );
    }

    public Object getCredentials() {
        return credentials;
    }

    public void setCredentials( Object credentials ) {
        this.credentials = credentials;
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
    public String toString() {
        return "Authentication information for user [" + getPrincipals() + "]";
    }

    /**
     * Merges the specified argument into this instance.
     * @param info the info to merge into this instance.
     */
    public void merge(AuthenticationInfo info) {
        if( this.principals == null ) {
            this.principals = new ArrayList<Object>();
        }
        //noinspection unchecked
        this.principals.addAll( info.getPrincipals() );

        if( this.credentials == null ) {
            setCredentials( info );
        }

        if( info.isAccountLocked() ) {
            setAccountLocked( true );
        }

        if( info.isCredentialsExpired() ) {
            setCredentialsExpired( true );
        }

        if( !info.isConcurrentLoginsAllowed() ) {
            setConcurrentLoginsAllowed( false );
        }
    }
}