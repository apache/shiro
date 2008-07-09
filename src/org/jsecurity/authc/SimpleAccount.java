/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jsecurity.authc;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;

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
public class SimpleAccount implements Account, Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    protected transient final Log logger = LogFactory.getLog(getClass());

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The principals that apply to the authenticated Subject/user.
     */
    private PrincipalCollection principals;

    /**
     * Credentials that were used to authenticate the user.
     */
    private Object credentials;

    /**
     * True if the account is locked, false otherwise.
     */
    private boolean locked = false;

    /**
     * True if the user's credentials are expired, false otherwise.
     */
    private boolean credentialsExpired = false;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SimpleAccount() {
    }

    public SimpleAccount(Object principal, Object credentials, String realmName) {
        this(principal instanceof PrincipalCollection ? (PrincipalCollection) principal : new SimplePrincipalCollection(realmName, principal), credentials);
    }

    public SimpleAccount(Collection principals, Object credentials, String realmName) {
        this(new SimplePrincipalCollection(realmName, principals), credentials);
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials) {
        this.principals = principals;
        this.credentials = credentials;
    }

    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public PrincipalCollection getPrincipals() {
        return this.principals;
    }

    public void setPrincipals(PrincipalCollection principals) {
        this.principals = principals;
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
     * Merges (adds) the specified Account data into this instance.
     *
     * This allows an instance of this class to be an <em>aggregation</em>, or <em>composition</em> of account data
     * from across multiple <code>Realm</code>s <tt>Realm</tt>s, not just one realm.
     *
     * <p>This is useful in a multi-realm authentication configuration - the individual <tt>Account</tt>
     * objects obtained from each realm can be {@link #merge merged} into this object.  This single object can then be
     * returned at the end of the authentication process, giving the impression of a single underlying
     * realm/data source.
     *
     * @param otherAccount the account whos data will be merged (added) into this instance.
     */
    @SuppressWarnings({"unchecked"})
    public void merge(Account otherAccount) {
        if (otherAccount == null) {
            return;
        }

        PrincipalCollection otherPrincipals = otherAccount.getPrincipals();
        if (otherPrincipals == null) {
            return;
        }

        PrincipalCollection thisPrincipals = getPrincipals();
        if (thisPrincipals == null) {
            setPrincipals(otherPrincipals);
        } else {
            //TODO - I don't like these checks - should be interface-based - Les.
            if (!(thisPrincipals instanceof SimplePrincipalCollection)) {
                throw new IllegalStateException("The " + getClass().getName() + " class expects its internal " +
                        PrincipalCollection.class.getName() + " instance to be an instance of the " +
                        SimplePrincipalCollection.class.getName() + " class.");
            }
            if (!(otherPrincipals instanceof SimplePrincipalCollection)) {
                throw new IllegalArgumentException("The " + getClass().getName() + " class expects the " +
                        "account argument's internal " +
                        PrincipalCollection.class.getName() + " instance to be an instance of the " +
                        SimplePrincipalCollection.class.getName() + " class.");
            }
            ((SimplePrincipalCollection) thisPrincipals).merge((SimplePrincipalCollection) otherPrincipals);
            setPrincipals(thisPrincipals);
        }

        Object otherCredentials = otherAccount.getCredentials();
        Object thisCredentials = getCredentials();
        if (thisCredentials == null) {
            setCredentials(otherCredentials);
        } else {
            HashSet set = new HashSet();
            if (thisCredentials instanceof Collection) {
                set.addAll((Collection) thisCredentials);
            } else {
                set.add(thisCredentials);
            }
            if (otherCredentials instanceof Collection) {
                set.addAll((Collection) otherCredentials);
            } else {
                set.add(otherCredentials);
            }
            setCredentials(set);
        }

        if (otherAccount.isLocked()) {
            setLocked(true);
        }

        if (otherAccount.isCredentialsExpired()) {
            setCredentialsExpired(true);
        }
    }

    public int hashCode() {
        return (getPrincipals() != null ? getPrincipals().hashCode() : 0);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SimpleAccount) {
            SimpleAccount sa = (SimpleAccount) o;
            //principal should be unique across the application, so only check this for equality:
            return (getPrincipals() != null ? getPrincipals().equals(sa.getPrincipals()) : sa.getPrincipals() == null);
        }
        return false;
    }

    public String toString() {
        return getPrincipals() != null ? getPrincipals().toString() : "empty";
    }
}