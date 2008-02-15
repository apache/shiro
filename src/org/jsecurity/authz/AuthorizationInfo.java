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
package org.jsecurity.authz;

import java.util.Collection;
import java.util.List;

/**
 * <p>An interface that must be returned by many {@link org.jsecurity.realm.Realm} implementations and is used to
 * represent the roles and permissions that a user account has in a framework independent way.
 *
 * <p>Used internally by any realm that extends from
 * {@link org.jsecurity.realm.AuthorizingRealm}, which
 * uses this object to encapsulate the cached information.</p>
 *
 * <p>Most realms will use {@link SimpleAuthorizationInfo} as the implementation of this interface, but are free
 * to create their own implementation.</p>
 *
 * @since 0.1
 * @author Jeremy Haile
 * @see SimpleAuthorizationInfo
 */
public interface AuthorizationInfo {
    
    /**
     * @see org.jsecurity.context.SecurityContext#hasRole(String)
     */
    boolean hasRole(String roleIdentifier);

    /**
     * @see org.jsecurity.context.SecurityContext#hasRoles(java.util.List)
     */
    boolean[] hasRoles(List<String> roleIdentifiers);

    /**
     * @see org.jsecurity.context.SecurityContext#hasAllRoles(java.util.Collection)
     */
    boolean hasAllRoles(Collection<String> roleIdentifiers);

    /**
     * @see org.jsecurity.context.SecurityContext#isPermitted(Permission)
     */
    boolean isPermitted(Permission permission);

    /**
     * @see org.jsecurity.context.SecurityContext#isPermittedPermissions(java.util.List)
     */
    boolean[] isPermitted(List<Permission> permissions);

    /**
     * @see org.jsecurity.context.SecurityContext#isPermittedAllPermissions(java.util.Collection)
     */
    boolean isPermittedAll(Collection<Permission> permissions);

    /**
     * @see org.jsecurity.context.SecurityContext#checkPermission(Permission)
     */
    void checkPermission(Permission permission) throws AuthorizationException;

    /**
     * @see org.jsecurity.context.SecurityContext#checkPermissionsPermissions(java.util.Collection)
     */
    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    /**
     * @see org.jsecurity.context.SecurityContext#checkRole(String)
     */
    void checkRole(String role);

    /**
     * @see org.jsecurity.context.SecurityContext#checkRoles
     */
    void checkRoles(Collection<String> roles);
}
