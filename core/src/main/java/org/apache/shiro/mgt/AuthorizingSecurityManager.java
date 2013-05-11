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
package org.apache.shiro.mgt;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.Authorizer;
import org.apache.shiro.authz.ModularRealmAuthorizer;
import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.LifecycleUtils;

import java.util.Collection;
import java.util.List;


/**
 * Shiro support of a {@link SecurityManager} class hierarchy that delegates all
 * authorization (access control) operations to a wrapped {@link Authorizer Authorizer} instance.  That is,
 * this class implements all the <tt>Authorizer</tt> methods in the {@link SecurityManager SecurityManager}
 * interface, but in reality, those methods are merely passthrough calls to the underlying 'real'
 * <tt>Authorizer</tt> instance.
 *
 * <p>All remaining <tt>SecurityManager</tt> methods not covered by this class or its parents (mostly Session support)
 * are left to be implemented by subclasses.
 *
 * <p>In keeping with the other classes in this hierarchy and Shiro's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon instantiation.
 *
 * @since 0.9
 */
public abstract class AuthorizingSecurityManager extends AuthenticatingSecurityManager {

    /**
     * The wrapped instance to which all of this <tt>SecurityManager</tt> authorization calls are delegated.
     */
    private Authorizer authorizer;

    /**
     * Default no-arg constructor that initializes an internal default
     * {@link org.apache.shiro.authz.ModularRealmAuthorizer ModularRealmAuthorizer}.
     */
    public AuthorizingSecurityManager() {
        super();
        this.authorizer = new ModularRealmAuthorizer();
    }

    /**
     * Returns the underlying wrapped <tt>Authorizer</tt> instance to which this <tt>SecurityManager</tt>
     * implementation delegates all of its authorization calls.
     *
     * @return the wrapped <tt>Authorizer</tt> used by this <tt>SecurityManager</tt> implementation.
     */
    public Authorizer getAuthorizer() {
        return authorizer;
    }

    /**
     * Sets the underlying <tt>Authorizer</tt> instance to which this <tt>SecurityManager</tt> implementation will
     * delegate all of its authorization calls.
     *
     * @param authorizer the <tt>Authorizer</tt> this <tt>SecurityManager</tt> should wrap and delegate all of its
     *                   authorization calls to.
     */
    public void setAuthorizer(Authorizer authorizer) {
        if (authorizer == null) {
            String msg = "Authorizer argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        this.authorizer = authorizer;
    }

    /**
     * First calls <code>super.afterRealmsSet()</code> and then sets these same <code>Realm</code> objects on this
     * instance's wrapped {@link Authorizer Authorizer}.
     * <p/>
     * The setting of realms the Authorizer will only occur if it is an instance of
     * {@link org.apache.shiro.authz.ModularRealmAuthorizer ModularRealmAuthorizer}, that is:
     * <pre>
     * if ( this.authorizer instanceof ModularRealmAuthorizer ) {
     *     ((ModularRealmAuthorizer)this.authorizer).setRealms(realms);
     * }</pre>
     */
    protected void afterRealmsSet() {
        super.afterRealmsSet();
        if (this.authorizer instanceof ModularRealmAuthorizer) {
            ((ModularRealmAuthorizer) this.authorizer).setRealms(getRealms());
        }
    }

    public void destroy() {
        LifecycleUtils.destroy(getAuthorizer());
        this.authorizer = null;
        super.destroy();
    }

    public boolean isPermitted(PrincipalCollection principals, String permissionString) {
        return this.authorizer.isPermitted(principals, permissionString);
    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        return this.authorizer.isPermitted(principals, permission);
    }

    public boolean[] isPermitted(PrincipalCollection principals, String... permissions) {
        return this.authorizer.isPermitted(principals, permissions);
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        return this.authorizer.isPermitted(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, String... permissions) {
        return this.authorizer.isPermittedAll(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        return this.authorizer.isPermittedAll(principals, permissions);
    }

    public void checkPermission(PrincipalCollection principals, String permission) throws AuthorizationException {
        this.authorizer.checkPermission(principals, permission);
    }

    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        this.authorizer.checkPermission(principals, permission);
    }

    public void checkPermissions(PrincipalCollection principals, String... permissions) throws AuthorizationException {
        this.authorizer.checkPermissions(principals, permissions);
    }

    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions) throws AuthorizationException {
        this.authorizer.checkPermissions(principals, permissions);
    }

    public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
        return this.authorizer.hasRole(principals, roleIdentifier);
    }

    public boolean[] hasRoles(PrincipalCollection principals, List<String> roleIdentifiers) {
        return this.authorizer.hasRoles(principals, roleIdentifiers);
    }

    public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
        return this.authorizer.hasAllRoles(principals, roleIdentifiers);
    }

    public void checkRole(PrincipalCollection principals, String role) throws AuthorizationException {
        this.authorizer.checkRole(principals, role);
    }

    public void checkRoles(PrincipalCollection principals, Collection<String> roles) throws AuthorizationException {
        this.authorizer.checkRoles(principals, roles);
    }
    
    public void checkRoles(PrincipalCollection principals, String... roles) throws AuthorizationException {
        this.authorizer.checkRoles(principals, roles);
    }    
}
