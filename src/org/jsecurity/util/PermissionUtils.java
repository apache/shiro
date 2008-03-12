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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.permission.PermissionResolver;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class PermissionUtils {

    public static final String DOUBLE_QUOTE = "\"";
    public static final String COMMA = ",";

    protected static transient final Log log = LogFactory.getLog(PermissionUtils.class);

    public static Set<Permission> resolvePermissions(Collection<String> permissionStrings, PermissionResolver permissionResolver) {
        Set<Permission> permissions = new LinkedHashSet<Permission>(permissionStrings.size());
        for (String permissionString : permissionStrings) {
            permissions.add(permissionResolver.resolvePermission(permissionString));
        }
        return permissions;
    }

    public static Set<Permission> resolveDelimitedPermissions(String permissionsString, PermissionResolver permissionResolver) {
        return resolveDelimitedPermissions(permissionsString, permissionResolver, DOUBLE_QUOTE);
    }

    public static Set<String> toPermissionStrings(String permissionsString ) {
        return toPermissionStrings(permissionsString, COMMA);
    }

    public static Set<String> toPermissionStrings(String permissionsString, String delimiter) {

        //TODO - this won't work if a quoted string has internal commas!
        String[] tokens = permissionsString.split(delimiter);

        //check for quoted strings:
        Set<String> permDefinitions = new LinkedHashSet<String>();

        boolean quoted = false;
        StringBuffer permDefinition = new StringBuffer();

        for (String token : tokens) {

            if (token.startsWith(DOUBLE_QUOTE)) {
                token = token.substring(1);
                if (token.endsWith(DOUBLE_QUOTE)) {
                    token = token.substring(0, token.length() - 1);
                    permDefinition = new StringBuffer(token);
                } else {
                    quoted = true;
                    permDefinition = new StringBuffer(token).append(delimiter);
                }
            } else {
                if (token.endsWith(DOUBLE_QUOTE)) {
                    token = token.substring(0, token.length() - 1);
                    permDefinition.append(token);
                    quoted = false;
                } else {
                    permDefinition.append(token);

                }
            }

            if (!quoted && permDefinition.length() > 0) {
                permDefinitions.add(permDefinition.toString());
            }
        }

        return permDefinitions;
    }

    public static Set<Permission> resolveDelimitedPermissions(String permissionsString, PermissionResolver permissionResolver, String delimiter) {
        Set<String> permStrings = toPermissionStrings(delimiter);
        return resolvePermissions(permStrings, permissionResolver);
    }
}
