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
package org.apache.shiro.samples.sprhib.model;

import org.hibernate.annotations.Cache;
import org.hibernate.annotations.CacheConcurrencyStrategy;
import org.hibernate.annotations.Index;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple class that represents any User domain entity in any application.
 *
 * <p>Because this class performs its own Realm and Permission checks, and these can happen frequently enough in a
 * production application, it is highly recommended that the internal User {@link #getRoles} collection be cached
 * in a 2nd-level cache when using JPA and/or Hibernate.  The hibernate xml configuration for this sample application
 * does in fact do this for your reference (see User.hbm.xml - the 'roles' declaration).</p>
 */
@Entity
@Table(name="users")
@Cache(usage= CacheConcurrencyStrategy.READ_WRITE)
public class User  {

    private Long id;
    private String username;
    private String email;
    private String password;
    private Set<Role> roles = new HashSet<Role>();


    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    /**
     * Returns the username associated with this user account;
     *
     * @return the username associated with this user account;
     */
    @Basic(optional=false)
    @Column(length=100)
    @Index(name="idx_users_username")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Basic(optional=false)
    @Index(name="idx_users_email")
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    /**
     * Returns the password for this user.
     *
     * @return this user's password
     */
    @Basic(optional=false)
    @Column(length=255)
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }


    @ManyToMany
    @JoinTable(name="users_roles")
    @Cache(usage=CacheConcurrencyStrategy.READ_WRITE)
    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

}


