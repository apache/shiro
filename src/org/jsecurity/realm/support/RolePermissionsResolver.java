/*
 * Copyright (C) 2005-2007 Jeremy Haile, Les Hazlewood
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

package org.jsecurity.realm.support;

import org.jsecurity.authz.Permission;

import java.util.Collection;

/**
 * Interface that allows a set of permissions to be associated with a role.  Several built-in
 * <tt>Realms</tt> included with JSecurity only associate users with roles.  In order to associate these
 * roles with a set of permissions, a <tt>RolePermisionsResolver</tt> should be implemented and injected into
 * the <tt>Realm</tt>.
 *
 * @author Jeremy Haile
 * @since 0.2
 */
public interface RolePermissionsResolver {

    /**
     * Returns the permissions that are associated with the given role name.  These permissions will be
     * associated with any user who is a member of the given role.
     * @param roleName the name of the role whose permissions should be returned.
     * @return a collection of permissions that are associated with the specified role name. 
     */
    Collection<Permission> getPermissionsForRole( String roleName );

}