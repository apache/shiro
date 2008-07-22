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
package org.jsecurity.authz;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple value object implementation of the {@link AuthorizationInfo} interface that stores roles and permissions.
 *
 * @author Jeremy Haile
 * @since 0.9
 * @see org.jsecurity.realm.AuthorizingRealm
 */
public class SimpleAuthorizationInfo implements AuthorizationInfo {

    protected Set<String> roles;

    protected Set<String> stringPermissions;

    protected Set<Permission> objectPermissions;

    public SimpleAuthorizationInfo() {
    }

    public SimpleAuthorizationInfo(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public void addRole( String role ) {
        if( this.roles == null ) {
            this.roles = new HashSet<String>();
        }
        this.roles.add( role );
    }

    public void addRoles( Collection<String> roles ) {
        if( this.roles == null ) {
            this.roles = new HashSet<String>();
        }
        this.roles.addAll( roles );
    }

    public Set<String> getStringPermissions() {
        return stringPermissions;
    }

    public void setStringPermissions(Set<String> stringPermissions) {
        this.stringPermissions = stringPermissions;
    }

    public void addStringPermission( String permission ) {
        if( this.stringPermissions == null ) {
            this.stringPermissions = new HashSet<String>();
        }
        this.stringPermissions.add( permission );
    }


    public void addStringPermissions( Collection<String> permissions ) {
        if( this.stringPermissions == null ) {
            this.stringPermissions = new HashSet<String>();
        }
        this.stringPermissions.addAll( permissions );
    }

    public Set<Permission> getObjectPermissions() {
        return objectPermissions;
    }

    public void setObjectPermissions(Set<Permission> objectPermissions) {
        this.objectPermissions = objectPermissions;
    }

    public void addObjectPermission( Permission permission ) {
        if( this.objectPermissions == null ) {
            this.objectPermissions = new HashSet<Permission>();
        }
        this.objectPermissions.add( permission );
    }

    public void addObjectPermissions( Collection<Permission> permissions ) {
        if( this.objectPermissions == null ) {
            this.objectPermissions = new HashSet<Permission>();
        }
        this.objectPermissions.addAll( permissions );
    }
}
