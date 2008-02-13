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

import org.jsecurity.authc.Account;
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.Authenticator;
import org.jsecurity.authc.event.AuthenticationEventListener;
import org.jsecurity.authc.event.AuthenticationEventListenerRegistrar;
import org.jsecurity.authc.support.ModularRealmAuthenticator;
import org.jsecurity.realm.Realm;
import org.jsecurity.util.LifecycleUtils;

import java.util.Collection;

/**
 * JSecurity support of a {@link org.jsecurity.SecurityManager} class hierarchy that delegates all
 * authentication operations to a wrapped {@link Authenticator Authenticator} instance.  That is, this class
 * implements all the <tt>Authenticator</tt> methods in the {@link SecurityManager SecurityManager}
 * interface, but in reality, those methods are merely passthrough calls to the underlying 'real'
 * <tt>Authenticator</tt> instance.
 *
 * <p>All other <tt>SecurityManager</tt> (authorization, session, etc) methods are left to be implemented by subclasses. 
 *
 * <p>In keeping with the other classes in this hierarchy and JSecurity's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon {@link #init() initialization} if
 * they have not been provided.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public abstract class AuthenticatingSecurityManager extends RealmSecurityManager implements AuthenticationEventListenerRegistrar {

    protected Authenticator authenticator;
    private Collection<AuthenticationEventListener> authenticationEventListeners = null;

    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public AuthenticatingSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application (automatically calls {@link #init()} before returning).
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public AuthenticatingSecurityManager(Realm singleRealm) {
        super(singleRealm);
    }

    /**
     * Supporting constructor that sets the {@link #setRealms realms} property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public AuthenticatingSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }

    protected Authenticator getRequiredAuthenticator() {
        Authenticator authc = getAuthenticator();
        if (authc == null) {
            String msg = "No authenticator attribute configured for this SecurityManager instance.  Please ensure " +
                "the init() method is called prior to using this instance and a default one will be created.";
            throw new IllegalStateException(msg);
        }
        return authc;
    }

    public Collection<AuthenticationEventListener> getAuthenticationEventListeners() {
        return authenticationEventListeners;
    }

    /**
     * This is a convenience method that allows registration of AuthenticationEventListeners with the underlying
     * delegate Authenticator instance at startup.
     *
     * <p>This is more convenient than having to configure your own Authenticator instance, inject the listeners on
     * it, and then set that Authenticator instance as an attribute of this class.  Instead, you can just rely
     * on the <tt>SecurityManager</tt>'s default initialization logic to create the Authenticator instance for you
     * and then apply these <tt>AuthenticationEventListener</tt>s on your behalf.
     *
     * <p>One notice however: The underlying Authenticator delegate must implement the
     * {@link org.jsecurity.authc.event.AuthenticationEventListenerRegistrar AuthenticationEventListenerRegistrar} interface in order for these
     * listeners to be applied.  If it does not implement this interface, it is considered a configuration error and
     * an exception will be thrown during {@link #init() initialization}.
     *
     * @param listeners the <tt>AuthenticationEventListener</tt>s to register with the underlying delegate
     * <tt>Authenticator</tt> at startup.
     */
    public void setAuthenticationEventListeners(Collection<AuthenticationEventListener> listeners) {
        this.authenticationEventListeners = listeners;
    }

    public void add(AuthenticationEventListener listener) {
        Authenticator authc = getRequiredAuthenticator();
        assertAuthenticatorEventListenerSupport(authc);
        ((AuthenticationEventListenerRegistrar)authc).add(listener);
    }

    public boolean remove(AuthenticationEventListener listener) {
        Authenticator authc = getAuthenticator();
        return (authc instanceof AuthenticationEventListenerRegistrar) &&
            ((AuthenticationEventListenerRegistrar)authc).remove(listener);
    }

    protected Authenticator createAuthenticator() {
        ModularRealmAuthenticator mra = new ModularRealmAuthenticator();
        mra.setRealms(getRealms());
        mra.init();
        return mra;
    }

    protected void ensureAuthenticator() {
        if (getAuthenticator() == null) {
            Authenticator authc = createAuthenticator();
            setAuthenticator(authc);
        }
    }

    private void assertAuthenticatorEventListenerSupport(Authenticator authc) {
        if (!(authc instanceof AuthenticationEventListenerRegistrar)) {
            String msg = "AuthenticationEventListener registration failed:  The underlying Authenticator instance of " +
                "type [" + authc.getClass().getName() + "] does not implement the " +
                AuthenticationEventListenerRegistrar.class.getName() + " interface and therefore cannot support " +
                "runtime registration of AuthenticationEventListeners.";
            throw new IllegalStateException(msg);
        }
    }

    protected void registerAnyAuthenticationEventListeners() {
        Collection<AuthenticationEventListener> listeners = getAuthenticationEventListeners();
        if ( listeners != null ) {
            if ( listeners.isEmpty() ) {
                String msg = "AuthenticationEventListeners collection property was configured, but the collection does " +
                    "not contain any AuthenticationEventListener objects.  This is considered a configuration error.  " +
                    "If you do not have any listener instances, do not set the property with an empty collection.";
                throw new IllegalStateException(msg);
            }
            for( AuthenticationEventListener listener : listeners ) {
                add(listener);
            }
        }
    }

    protected void deregisterAnyAuthenticationEventListeners() {
        Collection<AuthenticationEventListener> listeners = getAuthenticationEventListeners();
        if ( listeners != null && !listeners.isEmpty() ) {
            for( AuthenticationEventListener listener : listeners ) {
                remove( listener );
            }
        }
    }

    protected void afterRealmsSet() {
        ensureAuthenticator();
        registerAnyAuthenticationEventListeners();
        afterAuthenticatorSet();
    }

    protected void afterAuthenticatorSet(){}

    protected void beforeAuthenticatorDestroyed(){}

    protected void destroyAuthenticator() {
        LifecycleUtils.destroy(getAuthenticator());
        this.authenticator = null;
        this.authenticationEventListeners = null;
    }

    protected void beforeRealmsDestroyed() {
        beforeAuthenticatorDestroyed();
        deregisterAnyAuthenticationEventListeners();
        destroyAuthenticator();
    }

    /** Delegates to the authenticator for authentication. */
    public Account authenticate(AuthenticationToken token) throws AuthenticationException {
        return getRequiredAuthenticator().authenticate(token);
    }
}
