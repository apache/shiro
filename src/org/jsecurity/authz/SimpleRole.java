/*
* Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.authz;

import java.io.Serializable;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A simple representation of a security role that has a name and a collection of permissions.  This object can be
 * used internally by Realms to maintain authorization state.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class SimpleRole implements Serializable {

    protected String name = null;
    protected Set<Permission> permissions;

    public SimpleRole() {
    }

    public SimpleRole(String name) {
        setName(name);
    }

    public SimpleRole(String name, Set<Permission> permissions) {
        setName(name);
        setPermissions(permissions);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public void add(Permission permission) {
        Set<Permission> permissions = getPermissions();
        if (permissions == null) {
            permissions = new LinkedHashSet<Permission>();
            setPermissions(permissions);
        }
        permissions.add(permission);
    }

    public void addAll(Collection<Permission> perms) {
        if (perms != null && !perms.isEmpty()) {
            Set<Permission> permissions = getPermissions();
            if (permissions == null) {
                permissions = new LinkedHashSet<Permission>(perms.size());
                setPermissions(permissions);
            }
            permissions.addAll(perms);
        }
    }

    public boolean isPermitted(Permission p) {
        Collection<Permission> perms = getPermissions();
        if (perms != null && !perms.isEmpty()) {
            for (Permission perm : perms) {
                if (perm.implies(p)) {
                    return true;
                }
            }
        }
        return false;
    }

    public int hashCode() {
        return (getName() != null ? getName().hashCode() : 0);
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof SimpleRole) {
            SimpleRole sr = (SimpleRole) o;
            //only check name, since role names should be unique across an entire application:
            return (getName() != null ? getName().equals(sr.getName()) : sr.getName() == null);
        }
        return false;
    }

    public String toString() {
        return getName();
    }
}
