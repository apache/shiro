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

import org.jsecurity.authc.Account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Simple implementation of the {@link org.jsecurity.authc.Account} interface that
 * contains all necessary information as instance variables and exposes them
 * via getters and setters using standard JavaBean notation.
 *
 * @see org.jsecurity.authc.Account
 *
 * @since 0.1
 * @author Jeremy Haile
 */
public class SimpleAccount implements Account, Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The principals that apply to the subject/user who has been authenticated.
     */
    private List<Object> principals = null;

    /**
     * Credentials that were used to authenticate the user.
     */
    private Object credentials = null;

    /**
     * True if the account is locked, false otherwise.
     */
    private boolean locked = false;

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
    public SimpleAccount() {
    }

    public SimpleAccount( Object principal, Object credentials) {
        addPrincipal( principal );
        this.credentials = credentials;
    }

    public SimpleAccount(List<?> principals, Object credentials) {
        setPrincipals( principals );
        this.credentials = credentials;
    }

    public SimpleAccount(List<?> principals, Object credentials, boolean locked, boolean credentialsExpired) {
        setPrincipals( principals );
        this.credentials = credentials;
        this.locked = locked;
        this.credentialsExpired = credentialsExpired;
    }

    public SimpleAccount(List<?> principals, Object credentials, boolean locked, boolean credentialsExpired, boolean concurrentLoginsAllowed) {
        setPrincipals( principals );
        this.credentials = credentials;
        this.locked = locked;
        this.credentialsExpired = credentialsExpired;
        this.concurrentLoginsAllowed = concurrentLoginsAllowed;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public Object getPrincipal() {
        if( this.principals == null || this.principals.isEmpty()) {
            return null;
        } else {
            return this.principals.get(0);
        }
    }

    public List<Object> getPrincipals() {
        return Collections.unmodifiableList( principals );
    }

    public void setPrincipals(List<?> principals) {
        this.principals = new ArrayList<Object>( principals.size() );
        this.principals.addAll( principals );
    }

    public void addPrincipal( Object principal ) {
        if ( this.principals == null ) {
            this.principals = new ArrayList<Object>();
        }
        this.principals.add( principal );
    }

    public Object getCredentials() {
        return credentials;
    }

    public void setCredentials( Object credentials ) {
        this.credentials = credentials;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
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
        return "SimpleAccount for user [" + getPrincipals() + "]";
    }

    /**
     * Merges the specified argument into this instance.
     * @param account the account to merge into this instance.
     */
    public void merge(Account account) {
        if ( account == null ) {
            return;
        }

        //noinspection unchecked
        List<?> infoPrincipals = account.getPrincipals();

        if ( infoPrincipals != null && !infoPrincipals.isEmpty() ) {
            if ( this.principals == null ) {
                this.principals = new ArrayList<Object>( infoPrincipals.size() );
            }
            this.principals.addAll( infoPrincipals );
        }

        if( this.credentials == null ) {
            setCredentials(account);
        }

        if( account.isLocked() ) {
            setLocked( true );
        }

        if( account.isCredentialsExpired() ) {
            setCredentialsExpired( true );
        }

        if( !account.isConcurrentLoginsAllowed() ) {
            setConcurrentLoginsAllowed( false );
        }
    }
}