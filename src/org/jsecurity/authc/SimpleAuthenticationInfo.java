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

import org.jsecurity.subject.MutablePrincipalCollection;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.subject.SimplePrincipalCollection;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple value object implementation of the {@link MergableAuthenticationInfo} interface that holds the principals and
 * credentials.
 *
 * @author Jeremy Haile
 * @see org.jsecurity.realm.AuthenticatingRealm
 * @since 0.9
 */
public class SimpleAuthenticationInfo implements MergableAuthenticationInfo {

    protected PrincipalCollection principals;
    protected Object credentials;

    public SimpleAuthenticationInfo() {
    }

    public SimpleAuthenticationInfo(Object principal, Object credentials, String realmName) {
        this.principals = new SimplePrincipalCollection(principal, realmName);
        this.credentials = credentials;
    }

    public SimpleAuthenticationInfo(PrincipalCollection principals, Object credentials) {
        this.principals = new SimplePrincipalCollection(principals);
        this.credentials = credentials;
    }

    public PrincipalCollection getPrincipals() {
        return principals;
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

    @SuppressWarnings("unchecked")
    public void merge(AuthenticationInfo info) {
        if (info == null || info.getPrincipals() == null || info.getPrincipals().isEmpty()) {
            return;
        }

        if (this.principals == null) {
            this.principals = info.getPrincipals();
        } else {
            if (this.principals instanceof MutablePrincipalCollection) {
                ((MutablePrincipalCollection) this.principals).addAll(info.getPrincipals());
            } else {
                this.principals = new SimplePrincipalCollection(this.principals);
            }
        }

        Object thisCredentials = getCredentials();
        Object otherCredentials = info.getCredentials();

        if (otherCredentials == null) {
            return;
        }

        if (thisCredentials == null) {
            this.credentials = otherCredentials;
            return;
        }

        if (!(thisCredentials instanceof Collection)) {
            Set newSet = new HashSet();
            newSet.add(thisCredentials);
            setCredentials(newSet);
        }

        // At this point, the credentials should be a collection
        Collection credentialCollection = (Collection) getCredentials();
        if (otherCredentials instanceof Collection) {
            credentialCollection.addAll((Collection) otherCredentials);
        } else {
            credentialCollection.add(otherCredentials);
        }
    }

    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SimpleAuthenticationInfo)) return false;

        SimpleAuthenticationInfo that = (SimpleAuthenticationInfo) o;

        if (principals != null ? !principals.equals(that.principals) : that.principals != null) return false;

        return true;
    }

    public int hashCode() {
        return (principals != null ? principals.hashCode() : 0);
    }

    public String toString() {
        return principals.toString();
    }

}
