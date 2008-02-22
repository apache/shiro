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

import org.jsecurity.authc.Account;

import java.util.Collection;
import java.util.List;

/**
 * <p>An <tt>AuthorizingAccount</tt> is an {@link Account Account} that knows about its assiged roles and permissions
 * and can perform its own authorization (access control) checks.  It primarily exists as a support class for Realm
 * implementations that want to cache authorization state when doing an account lookup so multiple authorization checks
 * do not need to access the Realm's underlying data store repeatedly.
 *
 * <p>Of course, an <tt>AuthorizingAccount</tt> concept is only a convenience mechansim if JSecurity account caching
 * enabled.  Realm implementations are free to ignore this interface entirely and implement/override any of their
 * <tt>Realm</tt>'s {@link Authorizer Authorizer} methods to execute the authorization checks as they see fit.
 * ({@link org.jsecurity.realm.Realm Realm} is a sub-interface of {@link Authorizer Authorizer} and therefore must
 * implement those methods as well).
 * 
 * @see org.jsecurity.realm.AuthorizingRealm AuthorizingRealm
 *
 * @since 0.9
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @see SimpleAuthorizingAccount
 */
public interface AuthorizingAccount extends Account {
    
    /**
     * @see org.jsecurity.subject.Subject#isPermitted(Permission)
     */
    boolean isPermitted(Permission permission);

    /**
     * @see org.jsecurity.subject.Subject#isPermitted(java.util.List)
     */
    boolean[] isPermitted(List<Permission> permissions);

    /**
     * @see org.jsecurity.subject.Subject#isPermittedAll(java.util.Collection)
     */
    boolean isPermittedAll(Collection<Permission> permissions);

    /**
     * @see org.jsecurity.subject.Subject#checkPermission(Permission)
     */
    void checkPermission(Permission permission) throws AuthorizationException;

    /**
     * @see org.jsecurity.subject.Subject#checkPermissions(java.util.Collection)
     */
    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    /**
     * @see org.jsecurity.subject.Subject#hasRole(String)
     */
    boolean hasRole(String roleIdentifier);

    /**
     * @see org.jsecurity.subject.Subject#hasRoles(java.util.List)
     */
    boolean[] hasRoles(List<String> roleIdentifiers);

    /**
     * @see org.jsecurity.subject.Subject#hasAllRoles(java.util.Collection)
     */
    boolean hasAllRoles(Collection<String> roleIdentifiers);

    /**
     * @see org.jsecurity.subject.Subject#checkRole(String)
     */
    void checkRole(String role);

    /**
     * @see org.jsecurity.subject.Subject#checkRoles
     */
    void checkRoles(Collection<String> roles);
}
