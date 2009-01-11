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
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionListener;
import org.jsecurity.session.SessionListenerRegistrar;
import org.jsecurity.session.mgt.DefaultSessionManager;
import org.jsecurity.session.mgt.DelegatingSession;
import org.jsecurity.session.mgt.SessionManager;
import org.jsecurity.util.LifecycleUtils;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

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

    /**
     * The internal delegate <code>SessionManager</code> used by this security manager that manages all the
     * application's {@link Session Session}s.
     */
    protected SessionManager sessionManager;

    /**
     * Default no-arg constructor, internally creates a suitable default {@link SessionManager SessionManager} delegate
     * instance via the {@link #createSessionManager() createSessionManager()} method.
     */
    public SessionsSecurityManager() {
        setSessionManager(createSessionManager());
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

    /**
     * Returns this security manager's internal delegate {@link SessionManager SessionManager}.
     *
     * @return this security manager's internal delegate {@link SessionManager SessionManager}.
     * @see #setSessionManager(org.jsecurity.session.mgt.SessionManager) setSessionManager
     */
    public SessionManager getSessionManager() {
        return this.sessionManager;
    }

    /**
     * Constructs a new <code>SessionManager</code> instance to be used as the internal delegate for this security
     * manager.  After creation via the {@link #newSessionManagerInstance() newSessionManagerInstance()} call, the
     * internal {@link #getCacheManager CacheManager} is set on it if the session manager instance implements the
     * {@link CacheManagerAware CacheManagerAware} interface to allow it to utilize the cache manager for its own
     * internal caching needs.
     *
     * @return a new initialized {@link SessionManager SessionManager} to use as this security manager's internal
     *         delegate.
     */
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

    /**
     * Merely instantiates (but does not initalize) the default <code>SessionManager</code> implementation.  This method
     * merely returns <code>new {@link DefaultSessionManager DefaultSessionManager}()</code>.
     *
     * @return a new, uninitialized {@link SessionManager SessionManager} instance.
     */
    protected SessionManager newSessionManagerInstance() {
        return new DefaultSessionManager();
    }

    /**
     * Calls {@link AuthorizingSecurityManager#afterCacheManagerSet() super.afterCacheManagerSet()} and then immediately calls
     * {@link #applyCacheManagerToSessionManager() applyCacheManagerToSessionManager()} to ensure the
     * <code>CacheManager</code> is applied to the SessionManager as necessary.
     */
    protected void afterCacheManagerSet() {
        super.afterCacheManagerSet();
        applyCacheManagerToSessionManager();
    }

    /**
     * Ensures the internal delegate <code>SessionManager</code> is injected with the newly set
     * {@link #setCacheManager CacheManager} so it may use it for its internal caching needs.
     * <p/>
     * Note:  This implementation only injects the CacheManager into the SessionManager if the SessionManager
     * instance implements the {@link CacheManagerAware CacheManagerAware} interface.
     */
    protected void applyCacheManagerToSessionManager() {
        SessionManager sm = getSessionManager();
        if (sm instanceof CacheManagerAware) {
            ((CacheManagerAware) sm).setCacheManager(cacheManager);
        }
    }

    /**
     * This is a convenience method that allows registration of SessionListeners with the underlying delegate
     * SessionManager at startup.
     *
     * <p>This is more convenient than having to configure your own SessionManager instance, inject the listeners on
     * it, and then set that SessionManager instance as an attribute of this class.  Instead, you can just rely
     * on the <tt>SecurityManager</tt> to apply these <tt>SessionListener</tt>s on your behalf.
     *
     * <p>One notice however: The underlying SessionManager delegate must implement the
     * {@link SessionListenerRegistrar SessionListenerRegistrar} interface in order for these listeners to
     * be applied.  If it does not implement this interface, it is considered a configuration error and an exception
     * will be thrown.
     *
     * @param sessionListeners the <tt>SessionListener</tt>s to register with the underlying delegate
     *                         <tt>SessionManager</tt> at startup.
     */
    public void setSessionListeners(Collection<SessionListener> sessionListeners) {
        assertSessionListenerSupport();
        ((SessionListenerRegistrar) this.sessionManager).setSessionListeners(sessionListeners);
    }

    /**
     * Ensures the internal SessionManager instance is an <code>instanceof</code>
     * {@link org.jsecurity.session.SessionListenerRegistrar SessionListenerRegistrar} to ensure that any
     * listeners attempting to be registered can actually do so with the internal delegate instance.
     *
     * @throws IllegalStateException if the internal delegate SessionManager instance does not implement the
     *                               <code>SessionListenerRegistrar</code> interface.
     */
    private void assertSessionListenerSupport() throws IllegalStateException {
        if (!(this.sessionManager instanceof SessionListenerRegistrar)) {
            String msg = "SessionListener registration failed:  The underlying SessionManager instance of " +
                    "type [" + sessionManager.getClass().getName() + "] does not implement the " +
                    SessionListenerRegistrar.class.getName() + " interface and therefore cannot support " +
                    "session notifications.";
            throw new IllegalStateException(msg);
        }
    }

    /**
     * Asserts the internal delegate <code>SessionManager</code> instance
     * {@link #assertSessionListenerSupport() supports session listener registration} and then
     * {@link SessionListenerRegistrar#add adds} the listener to the
     * delegate instance.
     *
     * @param listener the <code>SessionListener</code> to register for session events.
     */
    public void add(SessionListener listener) {
        assertSessionListenerSupport();
        SessionManager sm = getSessionManager();
        ((SessionListenerRegistrar) sm).add(listener);
    }

    /**
     * Removes the specified listener from receiving session events from the internal delegate
     * {@link SessionManager} instance.
     *
     * @param listener the listener to remove that no longer wishes to be notified of session events.
     * @return <code>true</code> if the listener was removed from the internal delegate <code>SessionManager</code>
     *         instance, <code>false</code> otherwise.
     */
    public boolean remove(SessionListener listener) {
        SessionManager sm = getSessionManager();
        return (sm instanceof SessionListenerRegistrar) &&
                ((SessionListenerRegistrar) sm).remove(listener);
    }

    public Serializable start(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        return getSessionManager().start(originatingHost);
    }

    public Date getStartTimestamp(Serializable sessionId) {
        return getSessionManager().getStartTimestamp(sessionId);
    }

    public Date getLastAccessTime(Serializable sessionId) {
        return getSessionManager().getLastAccessTime(sessionId);
    }

    public boolean isValid(Serializable sessionId) {
        return getSessionManager().isValid(sessionId);
    }

    public long getTimeout(Serializable sessionId) throws InvalidSessionException {
        return getSessionManager().getTimeout(sessionId);
    }

    public void setTimeout(Serializable sessionId, long maxIdleTimeInMillis) throws InvalidSessionException {
        getSessionManager().setTimeout(sessionId, maxIdleTimeInMillis);
    }

    public void touch(Serializable sessionId) throws InvalidSessionException {
        getSessionManager().touch(sessionId);
    }

    public InetAddress getHostAddress(Serializable sessionId) {
        return getSessionManager().getHostAddress(sessionId);
    }

    public void stop(Serializable sessionId) throws InvalidSessionException {
        getSessionManager().stop(sessionId);
    }

    public Collection<Object> getAttributeKeys(Serializable sessionId) {
        return getSessionManager().getAttributeKeys(sessionId);
    }

    public Object getAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return getSessionManager().getAttribute(sessionId, key);
    }

    public void setAttribute(Serializable sessionId, Object key, Object value) throws InvalidSessionException {
        getSessionManager().setAttribute(sessionId, key, value);
    }

    public Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return getSessionManager().removeAttribute(sessionId, key);
    }

    /**
     * Template hook for subclasses that wish to perform clean up behavior during shutdown.
     */
    protected void beforeSessionManagerDestroyed() {
    }

    /**
     * Cleans up ('destroys') the internal delegate <code>SessionManager</code> by calling
     * {@link LifecycleUtils#destroy LifecycleUtils.destroy(getSessionManager())}.
     */
    protected void destroySessionManager() {
        LifecycleUtils.destroy(getSessionManager());
    }

    /**
     * Calls {@link #beforeSessionManagerDestroyed() beforeSessionManagerDestroyed()} to allow subclass clean up and
     * then immediatley calls {@link #destroySessionManager() destroySessionManager()} to clean up the internal
     * delegate instance.
     */
    protected void beforeAuthorizerDestroyed() {
        beforeSessionManagerDestroyed();
        destroySessionManager();
    }

    public Session getSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        SessionManager sm = getSessionManager();
        if (!sm.isValid(sessionId)) {
            String msg = "Specified id [" + sessionId + "] does not correspond to a valid Session  It either " +
                    "does not exist or the corresponding session has been stopped or expired.";
            throw new InvalidSessionException(msg, sessionId);
        }
        return new DelegatingSession(sm, sessionId);
    }

}
