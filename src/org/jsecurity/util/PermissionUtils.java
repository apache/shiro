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
package org.jsecurity.util;

import org.jsecurity.authz.Permission;
import org.jsecurity.authz.permission.PermissionResolver;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class PermissionUtils {

    public static Set<Permission> resolveDelimitedPermissions(String s, PermissionResolver permissionResolver) {
        Set<String> permStrings = toPermissionStrings(s);
        return resolvePermissions(permStrings, permissionResolver);
    }

    public static Set<String> toPermissionStrings(String permissionsString) {
        String[] tokens = StringUtils.split(permissionsString);
        if ( tokens != null && tokens.length > 0 ) {
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
