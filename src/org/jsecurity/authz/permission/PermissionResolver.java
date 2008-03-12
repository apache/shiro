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
 * <p>A PermisisonResolver resolves a String value and converts it into a
 * {@link org.jsecurity.authz.Permission} instance.
 *
 * <p>The default {@link org.jsecurity.authz.permission.WildcardPermissionResolver} should be
 * suitable for most purposes, which constructs {@link org.jsecurity.authz.permission.WildcardPermission} objects.
 * However, any resolver may be configured if an application wishes to use different
 * {@link org.jsecurity.authz.Permission} implementations.</p>
 *
 * <p>A <tt>PermissionResolver</tt> is used by many JSecurity components such as annotations, property file
 * configuration, URL configuration, etc.  It is useful whenever a String representation of a permission is specified
 * and that String needs to be converted to a Permission instance before executing a security check.</p>
 *
 * @author Jeremy Haile
 * @since 0.9
 */
public interface PermissionResolver {

    /**
     * Resolves a Permission based on the given String representation.
     * @param permissionString the String representation of a permission.
     * @return A Permission object that can be used internally to determine a subject's permissions.
     * @throws InvalidPermissionStringException if the permission string is not valid for this resolver.
     */
    Permission resolvePermission( String permissionString );

}
