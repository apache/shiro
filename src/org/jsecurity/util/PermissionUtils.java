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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class PermissionUtils {

    protected static transient final Log log = LogFactory.getLog( PermissionUtils.class );

    public static List<Permission> resolvePermissions(Collection<String> permissionStrings, PermissionResolver permissionResolver) {
        List<Permission> permissionList = new ArrayList<Permission>(permissionStrings.size());
        for( String permissionString : permissionStrings ) {
            permissionList.add( permissionResolver.resolvePermission( permissionString ) );
        }
        return permissionList;
    }

    public static List<Permission> resolveDelimitedPermissions(String permissionsString, PermissionResolver permissionResolver, String delimiter) {
        String[] permissionStrings = permissionsString.split( delimiter );
        return resolvePermissions( Arrays.asList( permissionStrings ), permissionResolver );
    }
}
