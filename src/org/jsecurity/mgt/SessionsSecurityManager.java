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
package org.jsecurity.mgt;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.session.*;
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
 * possible, suitable default instances for all dependencies will be created upon instantiation.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class SessionsSecurityManager extends AuthorizingSecurityManager implements SessionListenerRegistrar {

    protected SessionManager sessionManager = createSessionManager();

    /**
     * Default no-arg constructor.
     */
    public SessionsSecurityManager() {
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
        SessionManager sm = newSessionManagerInstance();
        CacheManager cm = getCacheManager();
        if (cm != null) {
            if (sm instanceof CacheManagerAware) {
                ((CacheManagerAware) sm).setCacheManager(cm);
            }
        }
        return sm;
    }

    protected SessionManager newSessionManagerInstance() {
        return new DefaultSessionManager();
    }

    protected void afterCacheManagerSet() {
        super.afterCacheManagerSet();
        applyCacheManagerToSessionManager();
    }

    protected void applyCacheManagerToSessionManager() {
        SessionManager sm = getSessionManager();
        if (sm instanceof CacheManagerAware) {
            ((CacheManagerAware) sm).setCacheManager(cacheManager);
        }
    }

    /**
     * This is a convenience method that allows registration of SessionEventListeners with the underlying delegate
     * SessionManager at startup.
     *
     * <p>This is more convenient than having to configure your own SessionManager instance, inject the listeners on
     * it, and then set that SessionManager instance as an attribute of this class.  Instead, you can just rely
     * on the <tt>SecurityManager</tt> to apply these <tt>SessionEventListener</tt>s on your behalf.
     *
     * <p>One notice however: The underlying SessionManager delegate must implement the
     * {@link SessionListenerRegistrar SessionListenerRegistrar} interface in order for these listeners to
     * be applied.  If it does not implement this interface, it is considered a configuration error and an exception
     * will be thrown.
     *
     * @param sessionEventListeners the <tt>SessionEventListener</tt>s to register with the underlying delegate
     *                              <tt>SessionManager</tt> at startup.
     */
    public void setSessionListeners(Collection<SessionListener> sessionEventListeners) {
        assertSessionListenerSupport();
        ((SessionListenerRegistrar) this.sessionManager).setSessionListeners(sessionEventListeners);
    }

    private void assertSessionListenerSupport() {
        if (!(this.sessionManager instanceof SessionListenerRegistrar)) {
            String msg = "SessionListener registration failed:  The underlying SessionManager instance of " +
                    "type [" + sessionManager.getClass().getName() + "] does not implement the " +
                    SessionListenerRegistrar.class.getName() + " interface and therefore cannot support " +
                    "session notifications.";
            throw new IllegalStateException(msg);
        }
    }

    public void add(SessionListener listener) {
        assertSessionListenerSupport();
        SessionManager sm = getSessionManager();
        ((SessionListenerRegistrar) sm).add(listener);
    }

    public boolean remove(SessionListener listener) {
        SessionManager sm = getSessionManager();
        return (sm instanceof SessionListenerRegistrar) &&
                ((SessionListenerRegistrar) sm).remove(listener);
    }

    protected void beforeSessionManagerDestroyed() {
    }

    protected void destroySessionManager() {
        LifecycleUtils.destroy(getSessionManager());
    }

    protected void beforeAuthorizerDestroyed() {
        beforeSessionManagerDestroyed();
        destroySessionManager();
    }

    public Session start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        SessionManager sm = getSessionManager();
        Serializable sessionId = sm.start(hostAddress);
        return new DelegatingSession(sm, sessionId);
    }

    public Session getSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        SessionManager sm = getSessionManager();
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
