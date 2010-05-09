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
import org.apache.shiro.cache.CacheManagerAware;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.util.LifecycleUtils;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;
import java.util.Map;


/**
 * Shiro support of a {@link SecurityManager} class hierarchy that delegates all
 * {@link org.apache.shiro.session.Session session} operations to a wrapped {@link org.apache.shiro.session.mgt.SessionManager SessionManager}
 * instance.  That is, this class implements the methods in the
 * {@link SessionManager SessionManager} interface, but in reality, those methods are merely passthrough calls to
 * the underlying 'real' {@code SessionManager} instance.
 * <p/>
 * The remaining {@code SecurityManager} methods not implemented by this class or its parents are left to be
 * implemented by subclasses.
 * <p/>
 * In keeping with the other classes in this hierarchy and Shiro's desire to minimize configuration whenever
 * possible, suitable default instances for all dependencies will be created upon instantiation.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class SessionsSecurityManager extends AuthorizingSecurityManager {

    /**
     * The internal delegate <code>SessionManager</code> used by this security manager that manages all the
     * application's {@link Session Session}s.
     */
    private SessionManager sessionManager;

    /**
     * Default no-arg constructor, internally creates a suitable default {@link SessionManager SessionManager} delegate
     * instance.
     */
    public SessionsSecurityManager() {
        super();
        this.sessionManager = new DefaultSessionManager();
        applyCacheManagerToSessionManager();
    }

    /**
     * Sets the underlying delegate {@link SessionManager} instance that will be used to support this implementation's
     * <tt>SessionManager</tt> method calls.
     * <p/>
     * This <tt>SecurityManager</tt> implementation does not provide logic to support the inherited
     * <tt>SessionManager</tt> interface, but instead delegates these calls to an internal
     * <tt>SessionManager</tt> instance.
     * <p/>
     * If a <tt>SessionManager</tt> instance is not set, a default one will be automatically created and
     * initialized appropriately for the the existing runtime environment.
     *
     * @param sessionManager delegate instance to use to support this manager's <tt>SessionManager</tt> method calls.
     */
    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
        afterSessionManagerSet();
    }

    protected void afterSessionManagerSet() {
        applyCacheManagerToSessionManager();
    }

    /**
     * Returns this security manager's internal delegate {@link SessionManager SessionManager}.
     *
     * @return this security manager's internal delegate {@link SessionManager SessionManager}.
     * @see #setSessionManager(org.apache.shiro.session.mgt.SessionManager) setSessionManager
     */
    public SessionManager getSessionManager() {
        return this.sessionManager;
    }

    /**
     * Calls {@link org.apache.shiro.mgt.AuthorizingSecurityManager#afterCacheManagerSet() super.afterCacheManagerSet()} and then immediately calls
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
        if (this.sessionManager instanceof CacheManagerAware) {
            ((CacheManagerAware) this.sessionManager).setCacheManager(getCacheManager());
        }
    }

    public Serializable start(String host) throws AuthorizationException {
        return this.sessionManager.start(host);
    }

    public Serializable start(Map initData) throws AuthorizationException {
        return this.sessionManager.start(initData);
    }

    public Date getStartTimestamp(Serializable sessionId) {
        return this.sessionManager.getStartTimestamp(sessionId);
    }

    public Date getLastAccessTime(Serializable sessionId) {
        return this.sessionManager.getLastAccessTime(sessionId);
    }

    public boolean isValid(Serializable sessionId) {
        return this.sessionManager.isValid(sessionId);
    }

    public void checkValid(Serializable sessionId) throws InvalidSessionException {
        this.sessionManager.checkValid(sessionId);
    }

    public long getTimeout(Serializable sessionId) throws InvalidSessionException {
        return this.sessionManager.getTimeout(sessionId);
    }

    public void setTimeout(Serializable sessionId, long maxIdleTimeInMillis) throws InvalidSessionException {
        this.sessionManager.setTimeout(sessionId, maxIdleTimeInMillis);
    }

    public void touch(Serializable sessionId) throws InvalidSessionException {
        this.sessionManager.touch(sessionId);
    }

    public String getHost(Serializable sessionId) {
        return this.sessionManager.getHost(sessionId);
    }

    public void stop(Serializable sessionId) throws InvalidSessionException {
        this.sessionManager.stop(sessionId);
    }

    public Collection<Object> getAttributeKeys(Serializable sessionId) {
        return this.sessionManager.getAttributeKeys(sessionId);
    }

    public Object getAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return this.sessionManager.getAttribute(sessionId, key);
    }

    public void setAttribute(Serializable sessionId, Object key, Object value) throws InvalidSessionException {
        this.sessionManager.setAttribute(sessionId, key, value);
    }

    public Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return this.sessionManager.removeAttribute(sessionId, key);
    }

    public void destroy() {
        LifecycleUtils.destroy(getSessionManager());
        this.sessionManager = null;
    }
}
