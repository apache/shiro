/*
 * Copyright (C) 2005-2008 Jeremy Haile
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
package org.jsecurity.authz.permission;

import org.jsecurity.authz.Permission;

/**
 * <tt>PermissionResolver</tt> implementation that returns a new {@link WildcardPermission WildcardPermission}
 * based on the input string.
 *
 * @author Jeremy Haile
 * @since 0.9
 */
public class WildcardPermissionResolver implements PermissionResolver {

    /**
     * Returns a new {@link WildcardPermission WildcardPermission} instance constructed based on the specified
     * <tt>permissionString</tt>.
     *
     * @param permissionString the permission string to convert to a {@link Permission Permission} instance.
     * @return a new {@link WildcardPermission WildcardPermission} instance constructed based on the specified
     * <tt>permissionString</tt>
     */
    public Permission resolvePermission(String permissionString) {
        return new WildcardPermission( permissionString );
    }                                  
}
