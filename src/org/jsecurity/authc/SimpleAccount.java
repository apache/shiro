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
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.SimpleAuthorizationInfo;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;

import java.io.Serializable;
import java.util.Collection;
import java.util.Set;

/**
 * Simple implementation of the {@link org.jsecurity.authc.Account} interface that
 * contains principal and credential information as instance variables and exposes them
 * via getters and setters using standard JavaBean notation.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.1
 */
public class SimpleAccount implements Account, MergableAuthenticationInfo, Serializable {

    /*--------------------------------------------
    |             C O N S T A N T S             |
    ============================================*/
    protected transient final Log log = LogFactory.getLog(getClass());

    /*--------------------------------------------
    |    I N S T A N C E   V A R I A B L E S    |
    ============================================*/
    /**
     * The principals that apply to the authenticated Subject/user.
     */
    private SimpleAuthenticationInfo authcInfo;

    /**
     * The authorization information for this account.
     */
    private SimpleAuthorizationInfo authzInfo;

    /**
     * Indicates this account is locked.  This isn't honored by all <tt>Realms</tt> but is honored by
     * {@link org.jsecurity.realm.SimpleAccountRealm}.
     */
    private boolean locked;

    /**
     * Indicates credentials on this account are expired.  This isn't honored by all <tt>Realms</tt> but is honored by
     * {@link org.jsecurity.realm.SimpleAccountRealm}.
     */
    private boolean credentialsExpired;

    /*--------------------------------------------
    |         C O N S T R U C T O R S           |
    ============================================*/
    public SimpleAccount() {
    }

    public SimpleAccount(Object principal, Object credentials, String realmName) {
        this(principal instanceof PrincipalCollection ? (PrincipalCollection) principal : new SimplePrincipalCollection(principal, realmName), credentials);
    }

    public SimpleAccount(Collection principals, Object credentials, String realmName) {
        this(new SimplePrincipalCollection(principals, realmName), credentials);
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, credentials);
        this.authzInfo = new SimpleAuthorizationInfo();
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials, Set<String> roles) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roles);
    }

    public SimpleAccount(Object principal, Object credentials, String realmName, Set<String> roleNames, Set<Permission> permissions) {
        this.authcInfo = new SimpleAuthenticationInfo(new SimplePrincipalCollection(principal, realmName), credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roleNames);
        this.authzInfo.setObjectPermissions( permissions );
    }

    public SimpleAccount(Collection principals, Object credentials, String realmName, Set<String> roleNames, Set<Permission> permissions) {
        this.authcInfo = new SimpleAuthenticationInfo(new SimplePrincipalCollection(principals, realmName), credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roleNames);
        this.authzInfo.setObjectPermissions( permissions );
    }

    public SimpleAccount(PrincipalCollection principals, Object credentials, Set<String> roleNames, Set<Permission> permissions) {
        this.authcInfo = new SimpleAuthenticationInfo(principals, credentials);
        this.authzInfo = new SimpleAuthorizationInfo(roleNames);
        this.authzInfo.setObjectPermissions( permissions );
    }


    /*--------------------------------------------
    |  A C C E S S O R S / M O D I F I E R S    |
    ============================================*/

    public PrincipalCollection getPrincipals() {
        return authcInfo.getPrincipals();
    }

    public void setPrincipals( PrincipalCollection principals ) {
        this.authcInfo.setPrincipals( principals );
    }

    public Object getCredentials() {
        return authcInfo.getCredentials();
    }

    public void setCredentials( Object credentials ) {
        this.authcInfo.setCredentials( credentials );
    }

    public Collection<String> getRoles() {
        return authzInfo.getRoles();
    }

    public void setRoles( Set<String> roles ) {
        this.authzInfo.setRoles( roles );
    }

    public void addRole( String role ) {
        this.authzInfo.addRole( role );
    }
    public void addRole( Collection<String> roles ) {
        this.authzInfo.addRoles( roles );
    }

    public Collection<String> getStringPermissions() {
        return authzInfo.getStringPermissions();
    }

    public void setStringPermissions( Set<String> permissions ) {
        this.authzInfo.setStringPermissions( permissions );
    }

    public void addStringPermission( String permission ) {
        this.authzInfo.addStringPermission( permission );
    }

    public void addStringPermissions( Collection<String> permissions ) {
        this.authzInfo.addStringPermissions( permissions );
    }

    public Collection<Permission> getObjectPermissions() {
        return authzInfo.getObjectPermissions();
    }

    public void setObjectPermissions( Set<Permission> permissions ) {
        this.authzInfo.setObjectPermissions( permissions );
    }

    public void addObjectPermission( Permission permission ) {
        this.authzInfo.addObjectPermission( permission );
    }

    public void addObjectPermissions( Collection<Permission> permissions ) {
        this.authzInfo.addObjectPermissions( permissions );
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


    public void merge(AuthenticationInfo info) {
        authcInfo.merge(info);

        // Merge SimpleAccount specific info
        if( info instanceof SimpleAccount ) {
            SimpleAccount otherAccount = (SimpleAccount) info;
            if (otherAccount.isLocked()) {
                setLocked(true);
            }

            if (otherAccount.isCredentialsExpired()) {
                setCredentialsExpired(true);
            }
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