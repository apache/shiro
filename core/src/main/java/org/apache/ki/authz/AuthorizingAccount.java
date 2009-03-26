/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.ki.authz;

import java.util.Collection;
import java.util.List;

import org.apache.ki.authc.Account;

/**
 * An <tt>AuthorizingAccount</tt> is an {@link Account Account} that knows about its assiged roles and permissions
 * and can perform its own authorization (access control) checks.  It primarily exists as a support class for Realm
 * implementations that want to cache authorization state when doing an account lookup so multiple authorization checks
 * do not need to access the Realm's underlying data store repeatedly.
 * <p/>
 * Of course, an <tt>AuthorizingAccount</tt> concept is only a convenience mechansim if Ki account caching
 * is enabled.  Realm implementations are free to ignore this interface entirely and implement/override any of their
 * <tt>Realm</tt>'s {@link Authorizer Authorizer} methods to execute the authorization checks as they see fit.
 * ({@link org.apache.ki.realm.Realm Realm} is a sub-interface of {@link Authorizer Authorizer} and therefore must
 * implement those methods as well).
 * <p/>
 * <b>DEPRECATION NOTE</b>: This interface and its default {@link SimpleAuthorizingAccount SimpleAuthorizingAccount}
 * implementation is deprecated and will be removed prior to 1.0 being released.  Instead, either just
 * return an {@link Account} instance, or if you want fine-grained control over authorization behavior, extend
 * a subclass of {@link org.apache.ki.realm.AuthorizingRealm} and implement your own security checks in the
 * Realm itself instead of forcing this logic in your entity/domain classes where it could be error prone and
 * unnecessarily couple these objects to Ki.
 *
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @see org.apache.ki.realm.AuthorizingRealm
 * @since 0.9
 * @deprecated
 */
public interface AuthorizingAccount extends Account {

    /**
     * @see org.apache.ki.subject.Subject#isPermitted(Permission)
     */
    boolean isPermitted(Permission permission);

    /**
     * @see org.apache.ki.subject.Subject#isPermitted(java.util.List)
     */
    boolean[] isPermitted(List<Permission> permissions);

    /**
     * @see org.apache.ki.subject.Subject#isPermittedAll(java.util.Collection)
     */
    boolean isPermittedAll(Collection<Permission> permissions);

    /**
     * @see org.apache.ki.subject.Subject#checkPermission(Permission)
     */
    void checkPermission(Permission permission) throws AuthorizationException;

    /**
     * @see org.apache.ki.subject.Subject#checkPermissions(java.util.Collection)
     */
    void checkPermissions(Collection<Permission> permissions) throws AuthorizationException;

    /**
     * @see org.apache.ki.subject.Subject#hasRole(String)
     */
    boolean hasRole(String roleIdentifier);

    /**
     * @see org.apache.ki.subject.Subject#hasRoles(java.util.List)
     */
    boolean[] hasRoles(List<String> roleIdentifiers);

    /**
     * @see org.apache.ki.subject.Subject#hasAllRoles(java.util.Collection)
     */
    boolean hasAllRoles(Collection<String> roleIdentifiers);

    /**
     * @see org.apache.ki.subject.Subject#checkRole(String)
     */
    void checkRole(String role);

    /**
     * @see org.apache.ki.subject.Subject#checkRoles
     */
    void checkRoles(Collection<String> roles);
}
