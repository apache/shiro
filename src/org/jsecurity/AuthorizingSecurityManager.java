/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.authz.ModularRealmAuthorizer;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.permission.PermissionResolver;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.LifecycleUtils;

import java.util.Collection;
import java.util.List;

/**
 * JSecurity support of a {@link org.jsecurity.SecurityManager} class hierarchy that delegates all authorization
 * (access control) operations to a wrapped {@link Authorizer Authorizer} instance.  That is,
 * this class implements all the <tt>Authorizer</tt> methods in the {@link SecurityManager SecurityManager}
 * interface, but in reality, those methods are merely passthrough calls to the underlying 'real'
 * <tt>Authorizer</tt> instance.
 *
 * <p>All other <tt>SecurityManager</tt> (session, etc) methods are left to be implemented by subclasses.
 *
 * <p>In keeping with the other classes in this hierarchy and JSecurity's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon {@link #init() initialization} if
 * they have not been provided.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class AuthorizingSecurityManager extends AuthenticatingSecurityManager {

    protected Authorizer authorizer = null;

    protected PermissionResolver permissionResolver = null;

    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public AuthorizingSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application (automatically calls {@link #init()} before returning).
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public AuthorizingSecurityManager(Realm singleRealm) {
        super(singleRealm);
    }

    /**
     * Supporting constructor that sets the {@link #setRealms realms} property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public AuthorizingSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    public Authorizer getAuthorizer() {
        return authorizer;
    }

    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    public PermissionResolver getPermissionResolver() {
        return permissionResolver;
    }

    public void setPermissionResolver(PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
    }

    protected Authorizer createAuthorizer() {
        ModularRealmAuthorizer mra = new ModularRealmAuthorizer();
        mra.setRealms(getRealms());
        mra.init();
        return mra;
    }

    protected void ensureAuthorizer() {
        if (getAuthorizer() == null) {
            Authorizer authz = createAuthorizer();
            setAuthorizer(authz);
        }
    }

    protected void afterAuthenticatorSet() {
        ensureAuthorizer();
        afterAuthorizerSet();
    }

    protected void afterAuthorizerSet(){}

    protected void beforeAuthorizerDestroyed(){}

    protected void destroyAuthorizer() {
        LifecycleUtils.destroy(getAuthorizer());
        this.authorizer = null;
    }

    protected void beforeAuthenticatorDestroyed() {
        beforeAuthorizerDestroyed();
        destroyAuthorizer();
    }

    protected Authorizer getRequiredAuthorizer() {
        Authorizer authz = getAuthorizer();
        if (authz == null) {
            String msg = "No authorizer attribute configured for this SecurityManager instance.  Please ensure " +
                "the init() method is called prior to using this instance and a default one will be created.";
            throw new IllegalStateException(msg);
        }
        return authz;
    }


    public boolean isPermitted(Object subjectIdentifier, String permissionString) {
        return getRequiredAuthorizer().isPermitted(subjectIdentifier, permissionString);
    }

    public boolean isPermitted(Object subjectIdentifier, Permission permission) {
        return getRequiredAuthorizer().isPermitted(subjectIdentifier, permission);
    }

    public boolean[] isPermitted(Object subjectIdentifier, String... permissions) {
        return getRequiredAuthorizer().isPermitted(subjectIdentifier, permissions );
    }

    public boolean[] isPermitted(Object subjectIdentifier, List<Permission> permissions) {
        return getRequiredAuthorizer().isPermitted(subjectIdentifier, permissions);
    }

    public boolean isPermittedAll(Object subjectIdentifier, String... permissions) {
        return getRequiredAuthorizer().isPermittedAll(subjectIdentifier, permissions);
    }

    public boolean isPermittedAll(Object subjectIdentifier, Collection<Permission> permissions) {
        return getRequiredAuthorizer().isPermittedAll(subjectIdentifier, permissions);
    }

    public void checkPermission(Object subjectIdentifier, String permission) throws AuthorizationException {
        getRequiredAuthorizer().checkPermission(subjectIdentifier, permission);
    }

    public void checkPermission(Object subjectIdentifier, Permission permission) throws AuthorizationException {
        getRequiredAuthorizer().checkPermission(subjectIdentifier, permission );
    }

    public void checkPermissions(Object subjectIdentifier, String... permissions) throws AuthorizationException {
        getRequiredAuthorizer().checkPermissions(subjectIdentifier, permissions);
    }

    public void checkPermissions(Object subjectIdentifier, Collection<Permission> permissions) throws AuthorizationException {
        getRequiredAuthorizer().checkPermissions(subjectIdentifier, permissions);
    }

    public boolean hasRole(Object subjectIdentifier, String roleIdentifier) {
        return getRequiredAuthorizer().hasRole(subjectIdentifier, roleIdentifier);
    }

    public boolean[] hasRoles(Object subjectIdentifier, List<String> roleIdentifiers) {
        return getRequiredAuthorizer().hasRoles(subjectIdentifier, roleIdentifiers);
    }

    public boolean hasAllRoles(Object subjectIdentifier, Collection<String> roleIdentifiers) {
        return getRequiredAuthorizer().hasAllRoles(subjectIdentifier, roleIdentifiers);
    }

    public void checkRole(Object subjectIdentifier, String role) throws AuthorizationException {
        getRequiredAuthorizer().checkRole(subjectIdentifier, role);
    }

    public void checkRoles(Object subjectIdentifier, Collection<String> roles) throws AuthorizationException {
        getRequiredAuthorizer().checkRoles(subjectIdentifier, roles);
    }
}
