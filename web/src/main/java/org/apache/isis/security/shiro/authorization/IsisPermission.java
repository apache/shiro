/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.apache.isis.security.shiro.authorization;

import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.WildcardPermission;

public class IsisPermission extends WildcardPermission {

    private static final long serialVersionUID = 1L;
    private static final Pattern PATTERN = Pattern.compile("([!]?)([^/]+)[/](.+)");

    private static ThreadLocal<Map<String,List<IsisPermission>>> VETOING_PERMISSIONS = new ThreadLocal<Map<String,List<IsisPermission>>>() {
        protected java.util.Map<String,List<IsisPermission>> initialValue() { return Maps.newTreeMap(); }
    };

    public static void resetVetoedPermissions() {
        IsisPermission.VETOING_PERMISSIONS.get().clear();
    }

    static boolean isVetoed(String permissionGroup, Permission p) {
        if(permissionGroup == null) {
            return false;
        }
        List<IsisPermission> vetoingPermissions = VETOING_PERMISSIONS.get().get(permissionGroup);
        if(vetoingPermissions == null || vetoingPermissions.isEmpty()) {
            return false;
        }
        for(IsisPermission vetoingPermission: vetoingPermissions) {
            if(vetoingPermission.impliesWithoutVeto(p)) {
                return true;
            }
        }
        return false;
    }

    static void addVeto(IsisPermission vetoingPermission) {
        String permissionGroup = vetoingPermission.getPermissionGroup();
        List<IsisPermission> vetoingPermissions = IsisPermission.VETOING_PERMISSIONS.get().get(permissionGroup);
        if(vetoingPermissions == null) {
            vetoingPermissions = Lists.newArrayList();
            IsisPermission.VETOING_PERMISSIONS.get().put(permissionGroup, vetoingPermissions);
        }
        vetoingPermissions.add(vetoingPermission);
    }

    private boolean veto;
    private String permissionGroup;
    
    public IsisPermission() {
    }

    public IsisPermission(String wildcardString, boolean caseSensitive) {
        super(wildcardString, caseSensitive);
    }

    public IsisPermission(String wildcardString) {
        super(wildcardString);
    }
    
    @Override
    protected void setParts(String wildcardString, boolean caseSensitive) {
        Matcher matcher = PATTERN.matcher(wildcardString);
        if(matcher.matches()) {
            veto = matcher.group(1).length() > 0;
            permissionGroup = matcher.group(2);
            super.setParts(matcher.group(3), caseSensitive);
        } else {
            super.setParts(wildcardString, caseSensitive);    
        }
    }
    
    @Override
    public boolean implies(Permission p) {
        if(veto) {
            IsisPermission.addVeto(this);
            return false;
        } else {
            return !IsisPermission.isVetoed(this.permissionGroup, p) && super.implies(p);
        }
    }

    boolean impliesWithoutVeto(Permission p) {
        return super.implies(p);
    }

    String getPermissionGroup() {
        return permissionGroup;
    }


    @Override
    public boolean equals(Object other) {
        if (other instanceof IsisPermission) {
            IsisPermission ip = (IsisPermission) other;
            return permissionGroup.equals(ip.getPermissionGroup()) && super.equals(other);
        }
        return false;
    }

    @Override
    public int hashCode() {
        // good enough
        return super.hashCode();
    }

    @Override
    public String toString() {
        return (veto?"!":"") + (permissionGroup != null? permissionGroup + "/": "") + super.toString();
    }

}
