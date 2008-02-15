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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.Account;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;

/**
 * Simple implementation of the {@link org.jsecurity.authc.Account} interface that
 * contains all necessary information as instance variables and exposes them
 * via getters and setters using standard JavaBean notation.
 *
 * @author Jeremy Haile
 * @see org.jsecurity.authc.Account
 * @since 0.1
 */
public class SimpleAccount implements AggregateAccount, Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    protected transient final Log logger = LogFactory.getLog( getClass() );

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /** The principal that apply to the subject/user who has been authenticated. */
    private Object principal = null;

    /** Credentials that were used to authenticate the user. */
    private Object credentials = null;

    /** True if the account is locked, false otherwise. */
    private boolean locked = false;

    /** True if the user's credentials are expired, false otherwise. */
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

    public SimpleAccount(Object principal, Object credentials) {
        this(principal, credentials, false, false);
    }

    public SimpleAccount(Object principal, Object credentials, boolean locked, boolean credentialsExpired) {
        this(principal, credentials, locked, credentialsExpired, true);
    }

    public SimpleAccount(Object principal, Object credentials, boolean locked, boolean credentialsExpired, boolean concurrentLoginsAllowed) {
        this.principal = principal;
        this.credentials = credentials;
        this.locked = locked;
        this.credentialsExpired = credentialsExpired;
        this.concurrentLoginsAllowed = concurrentLoginsAllowed;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public Object getPrincipal() {
        return this.principal;
    }

    public void setPrincipal(Object principal) {
        this.principal = principal;
    }

    public Object getCredentials() {
        return credentials;
    }

    public void setCredentials(Object credentials) {
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
    /**
     * Merges the specified argument into this instance.
     *
     * @param otherAccount the otherAccount to merge into this instance.
     */
    @SuppressWarnings({"unchecked"})
    public void merge(Account otherAccount) {
        if (otherAccount == null) {
            return;
        }

        Object otherPrincipal = otherAccount.getPrincipal();
        if (otherPrincipal == null) {
            return;
        }

        Object thisPrincipal = getPrincipal();
        if (thisPrincipal == null) {
            this.principal = otherPrincipal;
        } else {
            HashSet set = new HashSet();
            if (thisPrincipal instanceof Collection) {
                set.addAll((Collection)thisPrincipal);
            } else {
                set.add( thisPrincipal );
            }
            if (otherPrincipal instanceof Collection) {
                set.addAll((Collection)otherPrincipal);
            } else {
                set.add(otherPrincipal);
            }
            this.principal = set;
        }


        if (this.credentials == null) {
            setCredentials(otherAccount.getCredentials());
        }

        if (otherAccount.isLocked()) {
            setLocked(true);
        }

        if (otherAccount.isCredentialsExpired()) {
            setCredentialsExpired(true);
        }

        if (!otherAccount.isConcurrentLoginsAllowed()) {
            setConcurrentLoginsAllowed(false);
        }
    }

    public int hashCode() {
        return ( getPrincipal() != null ? getPrincipal().hashCode() : 0 );
    }

    public boolean equals( Object o ) {
        if ( o == this ) {
            return true;
        }
        if ( o instanceof SimpleAccount ) {
            SimpleAccount sa = (SimpleAccount)o;
            //principal should be unique across the application, so only check this for equality:
            return ( getPrincipal() != null ? getPrincipal().equals( sa.getPrincipal() ) : sa.getPrincipal() == null );
        }
        return false;
    }

    public String toString() {
        return getPrincipal().toString();
    }
}