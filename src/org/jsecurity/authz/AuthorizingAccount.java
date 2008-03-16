/*
 * Copyright 2005-2008 Jeremy Haile, Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
 * is enabled.  Realm implementations are free to ignore this interface entirely and implement/override any of their
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
