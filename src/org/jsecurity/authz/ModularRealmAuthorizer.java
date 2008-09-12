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
package org.jsecurity.authz;

import org.jsecurity.authz.permission.PermissionResolver;
import org.jsecurity.authz.permission.PermissionResolverAware;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;

import java.util.Collection;
import java.util.List;

/**
 * A <tt>ModularRealmAuthorizer</tt> is an <tt>Authorizer</tt> implementation that consults one or more configured
 * {@link Realm Realm}s during an authorization operation.
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class ModularRealmAuthorizer implements Authorizer, PermissionResolverAware {

    /**
     * The realms to consult during any authorization check.
     */
    protected Collection<Realm> realms;

    /**
     * Default no-argument constructor, does nothing.
     */
    public ModularRealmAuthorizer() {
    }

    /**
     * Constructor that accepts the <code>Realm</code>s to consult during an authorization check.  Immediately calls
     * {@link #setRealms setRealms(realms)}.
     * @param realms the realms to consult during an authorization check.
     */
    public ModularRealmAuthorizer(Collection<Realm> realms) {
        setRealms(realms);
    }

    /**
     * Returns the realms wrapped by this <code>Authorizer</code> which are consulted during an authorization check.
     * @return the realms wrapped by this <code>Authorizer</code> which are consulted during an authorization check.
     */
    public Collection<Realm> getRealms() {
        return this.realms;
    }

    /**
     * Sets the realms wrapped by this <code>Authorizer</code> which are consulted during an authorization check.
     * @param realms the realms wrapped by this <code>Authorizer</code> which are consulted during an authorization check.
     */
    public void setRealms(Collection<Realm> realms) {
        this.realms = realms;
    }

    /**
     * Used by the {@link Authorizer Authorizer} implementation methods to ensure that the {@link #setRealms realms}
     * has been set.  The default implementation ensures the property is not null and not empty.
     *
     * @throws IllegalStateException if the <tt>realms</tt> property is configured incorrectly.
     */
    protected void assertRealmsConfigured() throws IllegalStateException {
        Collection<Realm> realms = getRealms();
        if (realms == null || realms.isEmpty()) {
            String msg = "Configuration error:  No realms have been configured!  One or more realms must be " +
                    "present to execute an authorization operation.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Sets the specified {@link PermissionResolver PermissionResolver} on any of the wrapped realms that implement
     * the {@link org.jsecurity.authz.permission.PermissionResolverAware PermissionResolverAware} interface.
     *
     * @param permissionResolver the permissionResolver to set on all of the wrapped realms that implement the
     * {@link org.jsecurity.authz.permission.PermissionResolverAware PermissionResolverAware} interface.
     */
    public void setPermissionResolver(PermissionResolver permissionResolver) {
        Collection<Realm> realms = getRealms();
        if (realms != null && !realms.isEmpty()) {
            for (Realm realm : realms) {
                if (realm instanceof PermissionResolverAware) {
                    ((PermissionResolverAware) realm).setPermissionResolver(permissionResolver);
                }
            }
        }
    }

    /**
     * Returns <code>true</code> if any of the configured realms'
     * {@link Realm#isPermitted(org.jsecurity.subject.PrincipalCollection, String)} returns <code>true</code>,
     * <code>false</code> otherwise.
     */
    public boolean isPermitted(PrincipalCollection principals, String permission) {
        assertRealmsConfigured();
        for (Realm realm : getRealms()) {
            if (realm.isPermitted(principals, permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns <code>true</code> if any of the configured realms'
     * {@link Realm#isPermitted(org.jsecurity.subject.PrincipalCollection, Permission)} call returns <code>true</code>,
     * <code>false</code> otherwise.
     */
    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        assertRealmsConfigured();
        for (Realm realm : getRealms()) {
            if (realm.isPermitted(principals, permission)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns <code>true</code> if any of the configured realms'
     * {@link Realm#isPermitted(org.jsecurity.subject.PrincipalCollection, String[])} call returns <code>true</code>,
     * <code>false</code> otherwise.
     */
    public boolean[] isPermitted(PrincipalCollection principals, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            boolean[] isPermitted = new boolean[permissions.length];
            for (int i = 0; i < permissions.length; i++) {
                isPermitted[i] = isPermitted(principals, permissions[i]);
            }
            return isPermitted;
        }
        return new boolean[0];
    }

    /**
     * Returns <code>true</code> if any of the configured realms' 
     * {@link Realm#isPermitted(org.jsecurity.subject.PrincipalCollection, List<Permission>)} call returns <code>true</code>,
     * <code>false</code> otherwise.
     */
    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        if (permissions != null && !permissions.isEmpty()) {
            boolean[] isPermitted = new boolean[permissions.size()];
            int i = 0;
            for (Permission p : permissions) {
                isPermitted[i++] = isPermitted(principals, p);
            }
            return isPermitted;
        }

        return new boolean[0];
    }

    /**
     * Returns <code>true</code> if any of the configured realms'
     * {@link Realm#isPermitted(org.jsecurity.subject.PrincipalCollection, String)} call returns <code>true</code>
     * for <em>all</em> of the specified string permissions, <code>false</code> otherwise.
     */
    public boolean isPermittedAll(PrincipalCollection principals, String... permissions) {
        if (permissions != null && permissions.length > 0) {
            for (String perm : permissions) {
                if (!isPermitted(principals, perm)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Returns <code>true</code> if any of the configured realms'
     * {@link Realm#isPermitted(org.jsecurity.subject.PrincipalCollection, Permission)} call returns <code>true</code>
     * for <em>all</em> of the specified Permissions, <code>false</code> otherwise.
     */
    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        if (permissions != null && !permissions.isEmpty()) {
            for (Permission permission : permissions) {
                if (!isPermitted(principals, permission)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * If !{@link #isPermitted(org.jsecurity.subject.PrincipalCollection, String) isPermitted(permission)}, throws
     * an <code>UnauthorizedException</code> otherwise returns quietly.
     */
    public void checkPermission(PrincipalCollection principals, String permission) throws AuthorizationException {
        if (!isPermitted(principals, permission)) {
            throw new UnauthorizedException("Subject does not have permission [" + permission + "]");
        }
    }

    /**
     * If !{@link #isPermitted(org.jsecurity.subject.PrincipalCollection, Permission) isPermitted(permission)}, throws
     * an <code>UnauthorizedException</code> otherwise returns quietly.
     */
    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        if (!isPermitted(principals, permission)) {
            throw new UnauthorizedException("Subject does not have permission [" + permission + "]");
        }
    }

    /**
     * If !{@link #isPermitted(org.jsecurity.subject.PrincipalCollection, String[]) isPermitted(permission)}, throws
     * an <code>UnauthorizedException</code> otherwise returns quietly.
     */
    public void checkPermissions(PrincipalCollection principals, String... permissions) throws AuthorizationException {
        if (permissions != null && permissions.length > 0) {
            for (String perm : permissions) {
                checkPermission(principals, perm);
            }
        }
    }

    /**
     * If !{@link #isPermitted(org.jsecurity.subject.PrincipalCollection, Permission) isPermitted(permission)} for
     * <em>all</em> the given Permissions, throws
     * an <code>UnauthorizedException</code> otherwise returns quietly.
     */
    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions) throws AuthorizationException {
        if (permissions != null) {
            for (Permission permission : permissions) {
                checkPermission(principals, permission);
            }
        }
    }

    /**
     * Returns <code>true</code> if any of the configured realms'
     * {@link Realm#hasRole(org.jsecurity.subject.PrincipalCollection, String)} call returns <code>true</code>,
     * <code>false</code> otherwise.
     */
    public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
        assertRealmsConfigured();
        for (Realm realm : getRealms()) {
            if (realm.hasRole(principals, roleIdentifier)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Calls {@link #hasRole(org.jsecurity.subject.PrincipalCollection, String)} for each role name in the specified
     * collection and places the return value from each call at the respective location in the returned array.
     */
    public boolean[] hasRoles(PrincipalCollection principals, List<String> roleIdentifiers) {
        if (roleIdentifiers != null && !roleIdentifiers.isEmpty()) {
            boolean[] hasRoles = new boolean[roleIdentifiers.size()];
            int i = 0;
            for (String roleId : roleIdentifiers) {
                hasRoles[i++] = hasRole(principals, roleId);
            }
            return hasRoles;
        }

        return new boolean[0];
    }

    /**
     * Returns <code>true</code> iff any of the configured realms'
     * {@link Realm#hasRole(org.jsecurity.subject.PrincipalCollection, String)} call returns <code>true</code> for
     * <em>all</em> roles specified, <code>false</code> otherwise.
     */
    public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
        for (String roleIdentifier : roleIdentifiers) {
            if (!hasRole(principals, roleIdentifier)) {
                return false;
            }
        }
        return true;
    }

    /**
     * If !{@link #hasRole(org.jsecurity.subject.PrincipalCollection, String) hasRole(role)}, throws
     * an <code>UnauthorizedException</code> otherwise returns quietly.
     */
    public void checkRole(PrincipalCollection principals, String role) throws AuthorizationException {
        if (!hasRole(principals, role)) {
            throw new UnauthorizedException("Subject does not have role [" + role + "]");
        }
    }

    /**
     * Calls {@link #checkRole(org.jsecurity.subject.PrincipalCollection, String) checkRole} for each role specified.
     */
    public void checkRoles(PrincipalCollection principals, Collection<String> roles) throws AuthorizationException {
        if (roles != null) {
            for (String role : roles) {
                checkRole(principals, role);
            }
        }
    }

}
