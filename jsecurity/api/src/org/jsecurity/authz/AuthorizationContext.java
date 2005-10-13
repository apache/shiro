/*
 * Copyright (C) 2005 Les A. Hazlewood, Jeremy Haile
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

import java.security.Permission;
import java.security.Principal;
import java.util.Collection;
import java.util.List;

/**
 * Provides all access control behavior for an authenticated subject.
 * An <tt>AuthorizationContext</tt> can only be acquired upon a successful login, as access
 * control behavior must be associated with a known identity.
 *
 * @see org.jsecurity.authc.Authenticator
 *
 * @since 1.0
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public interface AuthorizationContext {

    /**
     * Provides access to the principal represented by this authorization context.
     * @return the principal associated with this authorization context.
     */
    Principal getPrincipal();

    /**
     * Checks if the given role identifier is associated with this context.
     * @param roleIdentifier the role identifier that is being checked.
     * @return true if the user associated with this context has the role, false otherwise.
     */
    boolean hasRole( String roleIdentifier );

    /**
     * Checks a set of role identifiers to see if they are associated with this
     * context and returns a boolean array indicating which roles are associated
     * with this context.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasRole} invocations over the wire in client/server systems.
     * 
     * @param roleIdentifiers the role identifiers to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * roles in the given identifiers.  A true value indicates the user has the
     * role at that index.  False indicates the user does not have the role.
     */
    boolean[] hasRoles( List<String> roleIdentifiers );

    /**
     * Checks if the user has all of the given roles.
     * @param roleIdentifiers the roles to be checked.
     * @return true if the user has all roles, false otherwise.
     */
    boolean hasAllRoles( Collection<String> roleIdentifiers );

    /**
     * Checks if the given permission is associated with this context.
     * @param permission the permission that is being checked.
     * @return true if the user associated with this context has the permission, false otherwise.
     */
    boolean hasPermission( Permission permission );

    /**
     * Checks a set of permissions to see if they are associated with this
     * context and returns a boolean array indicating which permissions are associated
     * with this context.
     *
     * <p>This is primarily a performance-enhancing method to help reduce the number of
     * {@link #hasPermission} invocations over the wire in client/server systems.
     *
     * @param permissions the permissions to check for.
     * @return an array of booleans whose indices correspond to the index of the
     * permissions in the given list.  A true value indicates the user has the
     * permission at that index.  False indicates the user does not have the role.
     */
    boolean[] hasPermissions( List<Permission> permissions );

    /**
     * Checks if the user has all of the given permissions.
     * @param permissions the permissions to be checked.
     * @return true if the user has all permissions, false otherwise.
     */
    boolean hasAllPermissions( Collection<Permission> permissions );


    /**
     * A convenience method to check a permission that a user is assumed to have.
     * If the user does not have the given permission, an {@link AuthorizationException}
     * will be thrown.
     * @param permission the permission to check.
     * @throws AuthorizationException if the user does not have the permission.
     */
    void checkPermission( Permission permission ) throws AuthorizationException;


    /**
     * A convenience method for checking if a user has all of the given permissions.
     * @param permissions the permissions to check.
     * @throws AuthorizationException if the user does not have all of the given
     * permissions.
     */
    void checkPermissions( Collection<Permission> permissions ) throws AuthorizationException;

}
