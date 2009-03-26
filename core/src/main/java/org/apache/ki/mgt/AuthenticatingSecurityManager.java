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
package org.apache.ki.mgt;

import java.util.Collection;

import org.apache.ki.authc.AuthenticationException;
import org.apache.ki.authc.AuthenticationInfo;
import org.apache.ki.authc.AuthenticationListener;
import org.apache.ki.authc.AuthenticationListenerRegistrar;
import org.apache.ki.authc.AuthenticationToken;
import org.apache.ki.authc.Authenticator;
import org.apache.ki.authc.pam.AuthenticationStrategy;
import org.apache.ki.authc.pam.ModularRealmAuthenticator;
import org.apache.ki.util.LifecycleUtils;


/**
 * Ki support of a {@link SecurityManager} class hierarchy that delegates all
 * authentication operations to a wrapped {@link Authenticator Authenticator} instance.  That is, this class
 * implements all the <tt>Authenticator</tt> methods in the {@link SecurityManager SecurityManager}
 * interface, but in reality, those methods are merely passthrough calls to the underlying 'real'
 * <tt>Authenticator</tt> instance.
 *
 * <p>All other <tt>SecurityManager</tt> (authorization, session, etc) methods are left to be implemented by subclasses.
 *
 * <p>In keeping with the other classes in this hierarchy and Ki's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies are created upon instantiation.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AuthenticatingSecurityManager extends RealmSecurityManager implements AuthenticationListenerRegistrar {

    /**
     * The internal <code>Authenticator</code> delegate instance that this SecurityManager instance will use
     * to perform all authentication operations.
     */
    private Authenticator authenticator;

    /**
     * Default no-arg constructor that initializes its internal
     * <code>authenticator</code> instance to a
     * {@link org.apache.ki.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator}.
     */
    public AuthenticatingSecurityManager() {
        super();
        this.authenticator = new ModularRealmAuthenticator();
    }

    /**
     * Returns the delegate <code>Authenticator</code> instance that this SecurityManager uses to perform all
     * authentication operations.  Unless overridden by the
     * {@link #setAuthenticator(org.apache.ki.authc.Authenticator) setAuthenticator}, the default instance is a
     * {@link org.apache.ki.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator}.
     *
     * @return the delegate <code>Authenticator</code> instance that this SecurityManager uses to perform all
     *         authentication operations.
     */
    public Authenticator getAuthenticator() {
        return authenticator;
    }

    /**
     * Sets the delegate <code>Authenticator</code> instance that this SecurityManager uses to perform all
     * authentication operations.  Unless overridden by this method, the default instance is a
     * {@link org.apache.ki.authc.pam.ModularRealmAuthenticator ModularRealmAuthenticator}.
     *
     * @param authenticator the delegate <code>Authenticator</code> instance that this SecurityManager will use to
     *                      perform all authentication operations.
     * @throws IllegalArgumentException if the argument is <code>null</code>.
     */
    public void setAuthenticator(Authenticator authenticator) throws IllegalArgumentException {
        if (authenticator == null) {
            String msg = "Authenticator argument cannot be null.";
            throw new IllegalArgumentException(msg);
        }
        this.authenticator = authenticator;
    }

    /**
     * Sets the {@link org.apache.ki.authc.pam.AuthenticationStrategy} to use
     * in multi-realm environments.
     *
     * @param strategy the <code>AuthenticationStrategy</code> to use in multi-realm environments.
     */
    public void setAuthenticationStrategy(AuthenticationStrategy strategy) {
        if (!(this.authenticator instanceof ModularRealmAuthenticator)) {
            String msg = "Configuring a AuthenticationStrategy is only applicable when the underlying " +
                    "Authenticator implementation is a " + ModularRealmAuthenticator.class.getName() +
                    " implementation.  This SecurityManager has been configured with an Authenticator of type " +
                    this.authenticator.getClass().getName();
            throw new IllegalStateException(msg);
        }
        ((ModularRealmAuthenticator) this.authenticator).setAuthenticationStrategy(strategy);
    }

    /**
     * This is a convenience method that allows registration of AuthenticationListeners with the underlying
     * delegate Authenticator instance.
     *
     * <p>This is more convenient than having to configure your own Authenticator instance, inject the listeners on
     * it, and then set that Authenticator instance as an attribute of this class.  Instead, you can just rely
     * on the <tt>SecurityManager</tt>'s default initialization logic to create the Authenticator instance for you
     * and then apply these <tt>AuthenticationListener</tt>s on your behalf.
     *
     * <p>One notice however: The underlying Authenticator delegate must implement the
     * {@link org.apache.ki.authc.AuthenticationListenerRegistrar AuthenticationListenerRegistrar}
     * interface in order for these listeners to be applied.  If it does not implement this interface, it is
     * considered a configuration error and an exception will be thrown.
     *
     * <p>All of Ki's <tt>Authenticator</tt> implementations implement the
     * <tt>AuthenticationListenerRegistrar</tt> interface, so you would only need
     * to worry about an exception being thrown if you provided your own Authenticator instance and did not
     * implement it.
     *
     * @param listeners the <tt>AuthenticationListener</tt>s to register with the underlying delegate
     *                  <tt>Authenticator</tt>.
     */
    public void setAuthenticationListeners(Collection<AuthenticationListener> listeners) {
        assertAuthenticatorListenerSupport();
        if (!(this.authenticator instanceof AuthenticationListenerRegistrar)) {
            String msg = "Configuring a AuthenticationStrategy is only applicable when the underlying " +
                    "Authenticator implementation is a " + AuthenticationListenerRegistrar.class.getName() +
                    " implementation.  This SecurityManager has been configured with an Authenticator of type " +
                    this.authenticator.getClass().getName() + ", which does not implement that interface.";
            throw new IllegalStateException(msg);
        }
        ((AuthenticationListenerRegistrar) this.authenticator).setAuthenticationListeners(listeners);
    }

    public void add(AuthenticationListener listener) {
        assertAuthenticatorListenerSupport();
        ((AuthenticationListenerRegistrar) this.authenticator).add(listener);
    }

    public boolean remove(AuthenticationListener listener) {
        return (this.authenticator instanceof AuthenticationListenerRegistrar) &&
                ((AuthenticationListenerRegistrar) this.authenticator).remove(listener);
    }

    /**
     * Ensures that <code>this.authenticator</code> implements the
     * {@link org.apache.ki.authc.AuthenticationListenerRegistrar AuthenticationListenerRegistrar} interface to ensure
     * listeners can be registered.
     */
    private void assertAuthenticatorListenerSupport() {
        if (!(this.authenticator instanceof AuthenticationListenerRegistrar)) {
            String msg = "AuthenticationListener registration failed:  The underlying Authenticator instance of " +
                    "type [" + this.authenticator.getClass().getName() + "] does not implement the " +
                    AuthenticationListenerRegistrar.class.getName() + " interface and therefore cannot support " +
                    "runtime registration of AuthenticationListeners.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Passes on the {@link #getRealms() realms} to the internal delegate <code>Authenticator</code> instance so
     * that it may use them during authentication attempts.
     */
    protected void afterRealmsSet() {
        super.afterRealmsSet();
        if (this.authenticator instanceof ModularRealmAuthenticator) {
            ((ModularRealmAuthenticator) this.authenticator).setRealms(getRealms());
        }
    }

    /**
     * Delegates to the wrapped {@link org.apache.ki.authc.Authenticator Authenticator} for authentication.
     */
    public AuthenticationInfo authenticate(AuthenticationToken token) throws AuthenticationException {
        return this.authenticator.authenticate(token);
    }

    public void destroy() {
        LifecycleUtils.destroy(getAuthenticator());
        this.authenticator = null;
        super.destroy();
    }
}
