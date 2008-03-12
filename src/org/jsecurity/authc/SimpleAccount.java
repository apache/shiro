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
package org.jsecurity.authc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.pam.AggregateAccount;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;

/**
 * Simple implementation of the {@link org.jsecurity.authc.Account} interface that
 * contains principal and credential information as instance variables and exposes them
 * via getters and setters using standard JavaBean notation.
 *
 * <p>Realm implementations can use this for simple principal/credential accounts, but note:  
 *
 * <p>This class cannot perform its own authorization checks for roles and permissions.  It is therefore not sufficient
 * to use to back a Realm's {@link org.jsecurity.authz.Authorizer Authorizer} method implementations.  If you need
 * an Account object to perform role and permission checks itself, you might want to use instaces of
 * {@link org.jsecurity.authz.SimpleAuthorizingAccount SimpleAuthorizingAccount} instead of this class.
 *
 * <p>But note that a <tt>SimpleAuthorizingAccount</tt> object caches its roles and permission definitions and will not
 * persist any changes to these definitions back to the source Realm.  If you need dynamic runtime modification of Roles
 * and/or Permissions for any given account, your Realm implementation will need to perform the authorization checks
 * directly since instances of this class are primarily used for caching and could represent stale data.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @see org.jsecurity.authz.SimpleAuthorizingAccount
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
    /** The principal that apply to the authenticated Subject/user. */
    private Object principal = null;

    /** Credentials that were used to authenticate the user. */
    private Object credentials = null;

    /** True if the account is locked, false otherwise. */
    private boolean locked = false;

    /** True if the user's credentials are expired, false otherwise. */
    private boolean credentialsExpired = false;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SimpleAccount() {
    }

    public SimpleAccount(Object principal, Object credentials) {
        this(principal, credentials, false, false);
    }

    public SimpleAccount(Object principal, Object credentials, boolean locked, boolean credentialsExpired) {
        this.principal = principal;
        this.credentials = credentials;
        this.locked = locked;
        this.credentialsExpired = credentialsExpired;
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
        return getPrincipal() != null ? getPrincipal().toString() : "empty";
    }
}