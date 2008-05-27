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
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.ExpiredSessionException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.StoppedSessionException;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.mgt.SessionEventListenerRegistrar;
import org.jsecurity.session.mgt.DefaultSessionManager;
import org.jsecurity.session.mgt.DelegatingSession;
import org.jsecurity.session.mgt.SessionManager;
import org.jsecurity.util.LifecycleUtils;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;

/**
 * JSecurity support of a {@link SecurityManager} class hierarchy that delegates all
 * {@link org.jsecurity.session.Session session} operations to a wrapped {@link SessionManager SessionManager}
 * instance.  That is, this class implements the methods in the
 * {@link SessionManager SessionManager} interface, but in reality, those methods are merely passthrough calls to
 * the underlying 'real' <tt>SessionManager</tt> instance.
 *
 * <p>The remaining <tt>SecurityManager</tt> methods not implemented by this class or its parents are left to be
 * implemented by subclasses.
 *
 * <p>In keeping with the other classes in this hierarchy and JSecurity's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon {@link #init() initialization} if
 * they have not been provided.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class SessionsSecurityManager extends AuthorizingSecurityManager implements SessionEventListenerRegistrar {

    protected SessionManager sessionManager;
    protected Collection<SessionEventListener> sessionEventListeners = null;

    /**
     * Default no-arg constructor - used in IoC environments or when the programmer wishes to explicitly call
     * {@link #init()} after the necessary properties have been set.
     */
    public SessionsSecurityManager() {
    }

    /**
     * Supporting constructor for a single-realm application (automatically calls {@link #init()} before returning).
     *
     * @param singleRealm the single realm used by this SecurityManager.
     */
    public SessionsSecurityManager(Realm singleRealm) {
        super(singleRealm);
    }

    /**
     * Supporting constructor that sets the {@link #setRealms realms} property and then automatically calls {@link #init()}.
     *
     * @param realms the realm instances backing this SecurityManager.
     */
    public SessionsSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    /**
     * Sets the underlying delegate {@link SessionManager} instance that will be used to support this implementation's
     * <tt>SessionManager</tt> method calls.
     *
     * <p>This <tt>SecurityManager</tt> implementation does not provide logic to support the inherited
     * <tt>SessionManager</tt> interface, but instead delegates these calls to an internal
     * <tt>SessionManager</tt> instance.
     *
     * <p>If a <tt>SessionManager</tt> instance is not set, a default one will be automatically created and
     * initialized appropriately for the the existing runtime environment.
     *
     * @param sessionManager delegate instance to use to support this manager's <tt>SessionManager</tt> method calls.
     */
    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public SessionManager getSessionManager() {
        return this.sessionManager;
    }

    protected SessionManager createSessionManager() {
        DefaultSessionManager sessionManager = new DefaultSessionManager();
        if ( getCacheManager() != null ) {
            sessionManager.setCacheManager(getCacheManager());
        }
        if ( getSessionEventListeners() != null ) {
            sessionManager.setSessionEventListeners( getSessionEventListeners() );
        }
        sessionManager.init();
        return sessionManager;
    }

    protected void ensureSessionManager() {
        if (getSessionManager() == null) {
            if (log.isInfoEnabled()) {
                log.info("No delegate SessionManager instance has been set as a property of this class.  Creating a " +
                    "default SessionManager instance...");
            }
            SessionManager sessionManager = createSessionManager();
            setSessionManager(sessionManager);
        }
    }

    protected SessionManager getRequiredSessionManager() {
        if (getSessionManager() == null) {
            ensureSessionManager();
        }
        return getSessionManager();
    }

    public Collection<SessionEventListener> getSessionEventListeners() {
        return sessionEventListeners;
    }

    /**
     * This is a convenience method that allows registration of SessionEventListeners with the underlying delegate
     * SessionManager at startup.
     *
     * <p>This is more convenient than having to configure your own SessionManager instance, inject the listeners on
     * it, and then set that SessionManager instance as an attribute of this class.  Instead, you can just rely
     * on the <tt>SecurityManager</tt>'s default initialization logic to create the SessionManager instance for you
     * and then apply these <tt>SessionEventListener</tt>s on your behalf.
     *
     * <p>One notice however: The underlying SessionManager delegate must implement the
     * {@link SessionEventListenerRegistrar SessionEventListenerRegistrar} interface in order for these listeners to
     * be applied.  If it does not implement this interface, it is considered a configuration error and an exception
     * will be thrown during {@link #init() initialization}.
     *
     * @param sessionEventListeners the <tt>SessionEventListener</tt>s to register with the underlying delegate
     * <tt>SessionManager</tt> at startup.
     */
    public void setSessionEventListeners(Collection<SessionEventListener> sessionEventListeners) {
        this.sessionEventListeners = sessionEventListeners;
    }

    private void assertSessionEventListenerSupport(SessionManager sessionManager) {
        if (!(sessionManager instanceof SessionEventListenerRegistrar)) {
            String msg = "SessionEventListener registration failed:  The underlying SessionManager instance of " +
                "type [" + sessionManager.getClass().getName() + "] does not implement the " +
                SessionEventListenerRegistrar.class.getName() + " interface and therefore cannot support " +
                "runtime SessionEvent propagation.";
            throw new IllegalStateException(msg);
        }
    }

    public void add(SessionEventListener listener) {
        ensureSessionManager();
        SessionManager sm = getSessionManager();
        assertSessionEventListenerSupport(sm);
        ((SessionEventListenerRegistrar)sm).add(listener);
    }

    public boolean remove(SessionEventListener listener) {
        SessionManager sm = getSessionManager();
        return (sm instanceof SessionEventListenerRegistrar) &&
            ((SessionEventListenerRegistrar)sm).remove(listener);
    }

    protected void afterAuthorizerSet() {
        ensureSessionManager();
        afterSessionManagerSet();
    }

    protected void afterSessionManagerSet(){}

    protected void beforeSessionManagerDestroyed(){}

    protected void destroySessionManager() {
        LifecycleUtils.destroy(getSessionManager());
        this.sessionManager = null;
        this.sessionEventListeners = null;
    }

    protected void beforeAuthorizerDestroyed() {
        beforeSessionManagerDestroyed();
        destroySessionManager();
    }

    public Session start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        Serializable sessionId = getRequiredSessionManager().start(hostAddress);
        return new DelegatingSession(sessionManager, sessionId);
    }

    public Session getSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        SessionManager sm = getRequiredSessionManager();
        if (sm.isExpired(sessionId)) {
            String msg = "Session with id [" + sessionId + "] has expired and may not be used.";
            throw new ExpiredSessionException(msg);
        } else if (sm.isStopped(sessionId)) {
            String msg = "Session with id [" + sessionId + "] has been stopped and may not be used.";
            throw new StoppedSessionException(msg);
        }

        return new DelegatingSession(sm, sessionId);
    }

}
