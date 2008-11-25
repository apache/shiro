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
package org.jsecurity.samples.sprhib.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.Permission;
import org.jsecurity.samples.sprhib.entity.Entity;
import org.jsecurity.samples.sprhib.party.User;

import java.util.HashSet;
import java.util.Set;

/**
 * Created on: Sep 16, 2005 4:00:20 PM
 *
 * @author Les Hazlewood
 */
public class Role extends Entity {

    private static final Log log = LogFactory.getLog(Role.class);

    public static final String ROOT_ROLE_NAME = "root";
    public static final String PRIVATE_ROLE_NAME = "private";

    private String name;

    private String description;

    private User owner;

    private boolean isPrivate = false;

    private Set<Permission> permissions;

    public Role() {
    }

    public Role(String name) {
        this.name = name;
    }

    public Role(String name, User owner) {
        this.name = name;
        this.owner = owner;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isPrivate() {
        return isPrivate;
    }

    public void setPrivate(boolean isPrivate) {
        this.isPrivate = isPrivate;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    /**
     * Adds a Permission to this party's collection of
     * {@link #getPermissions() permissions}.
     *
     * <p>If the existing permissions collection is <tt>null</tt>,
     * a new collection will be created and assigned to this role and then the permission will
     * be added.
     *
     * <p>If the specified permission already exists in this role's collection, it will not
     * be added again.
     *
     * @param p the Permission to add/associate with this Role
     */
    public void add(Permission p) {
        Set<Permission> perms = getPermissions();
        if (perms == null) {
            perms = new HashSet<Permission>();
            setPermissions(perms);
        }
        perms.add(p);
    }

    public boolean remove(Permission p) {
        Set<Permission> perms = getPermissions();
        return perms != null && perms.remove(p);
    }

    public boolean isPermitted(Permission p) {
        Set<Permission> perms = getPermissions();
        if (perms != null && !perms.isEmpty()) {
            for (Permission perm : perms) {
                if (perm.implies(p)) {
                    if (log.isTraceEnabled()) {
                        String msg = "saved permission implies permission argument.  Role [" +
                                getName() + "] has permission";
                        log.trace(msg);
                    }
                    return true;
                }
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("No saved permissions implies the permission argument.  Role [" +
                    getName() + "] doesn't have the specified permission");
        }

        return false;
    }

    public boolean onEquals(Entity e) {
        if (e instanceof Role) {
            Role r = (Role) e;
            return getName().equals(r.getName()) &&
                    (owner != null ? owner.equals(r.getOwner()) : r.getOwner() == null);
        }

        return false;
    }

    public int hashCode() {
        int result = name.hashCode();
        result = 29 * result + (owner != null ? owner.hashCode() : 0);
        return result;
    }

    public StringBuffer toStringBuffer() {
        StringBuffer sb = super.toStringBuffer();
        sb.append(",name=").append(getName());
        sb.append(",description=[").append(getDescription()).append("]");
        sb.append(",permissions={").append("<lazy property omitted>").append("}");
        return sb;
    }

    /**
     * Returns a shallow copy (i.e. the owner and Permission instances in the permissions
     * collection copied into a new list instead of being cloned themselves).  This should be fine since permission
     * objects are immutable.
     */
    @Override
    @SuppressWarnings({"CloneDoesntDeclareCloneNotSupportedException"})
    public Object clone() {
        Role clone = (Role) super.clone();
        clone.setName(getName());
        clone.setDescription(getDescription());
        clone.setOwner(getOwner());
        Set<Permission> perms = getPermissions();
        if (perms != null && !perms.isEmpty()) {
            Set<Permission> permClones = new HashSet<Permission>(perms.size());
            for (Permission p : perms) {
                permClones.add(p);
            }
            clone.setPermissions(permClones);
        }

        return clone;
    }

    public void clearPermissions() {
        Set<Permission> perms = getPermissions();
        if (perms != null && !perms.isEmpty()) {
            permissions.clear();
        }
    }

}


