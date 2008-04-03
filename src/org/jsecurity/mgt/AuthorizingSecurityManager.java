/*
 * Copyright 2005-2008 Les Hazlewood
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
package org.jsecurity.mgt;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.Authorizer;
import org.jsecurity.authz.ModularRealmAuthorizer;
import org.jsecurity.authz.Permission;
import org.jsecurity.authz.permission.PermissionResolver;
import org.jsecurity.authz.permission.PermissionResolverAware;
import org.jsecurity.realm.Realm;
import org.jsecurity.subject.PrincipalCollection;
import org.jsecurity.util.LifecycleUtils;

import java.util.Collection;
import java.util.List;

/**
 * JSecurity support of a {@link SecurityManager} class hierarchy that delegates all
 * authorization (access control) operations to a wrapped {@link Authorizer Authorizer} instance.  That is,
 * this class implements all the <tt>Authorizer</tt> methods in the {@link SecurityManager SecurityManager}
 * interface, but in reality, those methods are merely passthrough calls to the underlying 'real'
 * <tt>Authorizer</tt> instance.
 *
 * <p>All remaining <tt>SecurityManager</tt> methods not covered by this class or its parents (mostly Session support)
 * are left to be implemented by subclasses.
 *
 * <p>In keeping with the other classes in this hierarchy and JSecurity's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon {@link #init() initialization} if
 * they have not been provided.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AuthorizingSecurityManager extends AuthenticatingSecurityManager implements PermissionResolverAware {

    /**
     * The wrapped instance to which all of this <tt>SecurityManager</tt> authorization calls are delegated.
     */
    protected Authorizer authorizer = null;

    /**
     * The <tt>PermissionResolver</tt> instance to pass to the wrapped <tt>Authorizer</tt> instance during init.
     */
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
     * <p>If you don't set this attribute, a suitable default instance will be created for you during
     * {@link #init initialization}.
     *
     * @param authorizer the <tt>Authorizer</tt> this <tt>SecurityManager</tt> should wrap and delegate all of its
     *                   authorization calls to.
     */
    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    /**
     * Returns the <tt>PermissionResolver</tt> instance that will be passed on to the underlying wrapped
     * {@link Authorizer Authorizer} instance during {@link #init() initialization}.
     *
     * <p>See the {@link #setPermissionResolver setPermissionResolver} method for more detail.
     *
     * @return the <tt>PermissionResolver</tt> instance that will be passed on to the underlying wrapped
     *         {@link Authorizer Authorizer} instance during {@link #init() initialization}.
     * @see #setPermissionResolver setPermissionResolver
     */
    public PermissionResolver getPermissionResolver() {
        return permissionResolver;
    }

    /**
     * Sets the <tt>PermissionResolver</tt> instance that will be passed on to the underlying default wrapped
     * {@link Authorizer Authorizer} instance during {@link #init() initialization}.
     *
     * <p>This is a convenience method:  it allows you to configure an application-wide
     * <tt>PermissionResolver</tt> on the <tt>SecurityManager</tt> instance, and it will trickle its way down to the
     * 'real' authorizer and/or underlying Realms.  This is easier to configure at the <tt>SecurityManager</tt> level
     * than constructing your own object graph just to configure a <tt>PermissionResolver</tt> instance on objects
     * deep in the graph.
     *
     * @param permissionResolver the <tt>PermissionResolver</tt> instance to set on the wrapped <tt>Authorizer</tt> if
     *                           and only if that Authorizer instance also implements the <tt>PermissionResolverAware</tt> interface.
     */
    public void setPermissionResolver(PermissionResolver permissionResolver) {
        this.permissionResolver = permissionResolver;
    }

    /**
     * Creates a new <tt>Authorizer</tt> to use as the wrapped instance for this <tt>SecurityManager</tt>
     * implementation.
     *
     * @return the new <tt>Authorizer</tt> to use as the wrapped instance for this <tt>SecurityManager</tt> implementation.
     */
    protected Authorizer createAuthorizer() {
        ModularRealmAuthorizer mra = new ModularRealmAuthorizer();
        mra.setRealms(getRealms());
        if ( getPermissionResolver() != null ) {
            mra.setPermissionResolver( getPermissionResolver() );
        }
        mra.init();
        return mra;
    }

    /**
     * Called during the init process, this method ensures that an underlying wrapped <tt>Authorizer</tt> instance will
     * exist to support all of this <tt>SecurityManager</tt>'s delegate authorization calls.  If one does not exist,
     * a default will be created via the {@link #createAuthorizer createAuthorizer()} method which will then be set as
     * an attribute of this class.
     */
    protected void ensureAuthorizer() {
        Authorizer authorizer = getAuthorizer();
        if ( authorizer == null) {
            authorizer = createAuthorizer();
            setAuthorizer(authorizer);
        }
    }

    /**
     * Implementation of parent class's template hook for initialization logic.  This implementation
     * {@link #ensureAuthorizer ensures} an <tt>Authorizer</tt> exists and is fully initialized and then calls
     * {@link #afterAuthorizerSet() afterAuthorizerSet()} for further subclass initialization logic.
     */
    protected void afterAuthenticatorSet() {
        ensureAuthorizer();
        afterAuthorizerSet();
    }

    /**
     * Template hook for subclasses to implement initialization logic.  This will be called after an
     * <tt>Authorizer</tt> instance is guaranteed to have been set and initialized on this <tt>SecurityManager</tt>
     * instance.
     */
    protected void afterAuthorizerSet() {
    }

    /**
     * Template hook for subclasses to implement destruction/cleanup logic.  This will be called before this
     * instance's <tt>Authorizer</tt> instance will be cleaned up.
     */
    protected void beforeAuthorizerDestroyed() {
    }

    /**
     * Cleanup method that destroys/cleans up the wrapped {@link #getAuthorizer Authorizer} instance.
     */
    protected void destroyAuthorizer() {
        LifecycleUtils.destroy(getAuthorizer());
        this.authorizer = null;
    }

    /**
     * Implementation of parent class's template hook for destruction/cleanup logic.
     *
     * <p>This implementation ensures subclasses are cleaned up first by calling
     * {@link #beforeAuthorizerDestroyed() beforeAuthorizerDestroyed()} and then actually cleans up the
     * wrapped <tt>Authorizer</tt> via the {@link #destroyAuthorizer() desroyAuthorizer()} method.
     */
    protected void beforeAuthenticatorDestroyed() {
        beforeAuthorizerDestroyed();
        destroyAuthorizer();
    }

    /**
     * Utility method that ensures a delegate {@link #getAuthorizer() Authorizer} instance exists as an attribute of
     * this class.  If it does not, an IllegalStateException will be thrown because that indicates this
     * <tt>SecurityManager</tt> instance was not properly {@link #init() initialized}.
     *
     * @return the delegate <tt>Authorizer</tt> instance used by this <tt>SecurityManager</tt>
     * @throws IllegalStateException if for some reason the <tt>Authorizer</tt> instance is <tt>null</tt>, indicating
     *                               this <tt>SecurityManager</tt> instance was not properly {@link #init() initialized}.
     */
    protected Authorizer getRequiredAuthorizer() throws IllegalStateException {
        Authorizer authz = getAuthorizer();
        if (authz == null) {
            String msg = "No authorizer attribute configured for this SecurityManager instance.  Please ensure " +
                    "the init() method is called prior to using this instance and a default one will be created.";
            throw new IllegalStateException(msg);
        }
        return authz;
    }


    public boolean isPermitted(PrincipalCollection principals, String permissionString) {
        return getRequiredAuthorizer().isPermitted(principals, permissionString);
    }

    public boolean isPermitted(PrincipalCollection principals, Permission permission) {
        return getRequiredAuthorizer().isPermitted(principals, permission);
    }

    public boolean[] isPermitted(PrincipalCollection principals, String... permissions) {
        return getRequiredAuthorizer().isPermitted(principals, permissions);
    }

    public boolean[] isPermitted(PrincipalCollection principals, List<Permission> permissions) {
        return getRequiredAuthorizer().isPermitted(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, String... permissions) {
        return getRequiredAuthorizer().isPermittedAll(principals, permissions);
    }

    public boolean isPermittedAll(PrincipalCollection principals, Collection<Permission> permissions) {
        return getRequiredAuthorizer().isPermittedAll(principals, permissions);
    }

    public void checkPermission(PrincipalCollection principals, String permission) throws AuthorizationException {
        getRequiredAuthorizer().checkPermission(principals, permission);
    }

    public void checkPermission(PrincipalCollection principals, Permission permission) throws AuthorizationException {
        getRequiredAuthorizer().checkPermission(principals, permission);
    }

    public void checkPermissions(PrincipalCollection principals, String... permissions) throws AuthorizationException {
        getRequiredAuthorizer().checkPermissions(principals, permissions);
    }

    public void checkPermissions(PrincipalCollection principals, Collection<Permission> permissions) throws AuthorizationException {
        getRequiredAuthorizer().checkPermissions(principals, permissions);
    }

    public boolean hasRole(PrincipalCollection principals, String roleIdentifier) {
        return getRequiredAuthorizer().hasRole(principals, roleIdentifier);
    }

    public boolean[] hasRoles(PrincipalCollection principals, List<String> roleIdentifiers) {
        return getRequiredAuthorizer().hasRoles(principals, roleIdentifiers);
    }

    public boolean hasAllRoles(PrincipalCollection principals, Collection<String> roleIdentifiers) {
        return getRequiredAuthorizer().hasAllRoles(principals, roleIdentifiers);
    }

    public void checkRole(PrincipalCollection principals, String role) throws AuthorizationException {
        getRequiredAuthorizer().checkRole(principals, role);
    }

    public void checkRoles(PrincipalCollection principals, Collection<String> roles) throws AuthorizationException {
        getRequiredAuthorizer().checkRoles(principals, roles);
    }
}
