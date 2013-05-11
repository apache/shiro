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
package org.apache.shiro.util;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.authz.permission.PermissionResolver;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * Utility class to help with String-to-Permission object resolution.
 *
 * @since 0.1
 */
public class PermissionUtils {

    public static Set<Permission> resolveDelimitedPermissions(String s, PermissionResolver permissionResolver) {
        Set<String> permStrings = toPermissionStrings(s);
        return resolvePermissions(permStrings, permissionResolver);
    }

    public static Set<String> toPermissionStrings(String permissionsString) {
        String[] tokens = StringUtils.split(permissionsString);
        if (tokens != null && tokens.length > 0) {
            return new LinkedHashSet<String>(Arrays.asList(tokens));
        }
        return null;
    }

    public static Set<Permission> resolvePermissions(Collection<String> permissionStrings, PermissionResolver permissionResolver) {
        Set<Permission> permissions = new LinkedHashSet<Permission>(permissionStrings.size());
        for (String permissionString : permissionStrings) {
            permissions.add(permissionResolver.resolvePermission(permissionString));
        }
        return permissions;
    }
}
