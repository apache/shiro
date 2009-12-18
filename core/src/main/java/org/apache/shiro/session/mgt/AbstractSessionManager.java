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
package org.apache.shiro.session.mgt;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.HostUnauthorizedException;
import org.apache.shiro.session.*;
import org.apache.shiro.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.*;


/**
 * TODO - complete JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public abstract class AbstractSessionManager implements SessionManager, SessionListenerRegistrar {

    protected static final long MILLIS_PER_SECOND = 1000;
    protected static final long MILLIS_PER_MINUTE = 60 * MILLIS_PER_SECOND;
    protected static final long MILLIS_PER_HOUR = 60 * MILLIS_PER_MINUTE;

    /**
     * Default main session timeout value, equal to {@code 30} minutes.
     */
    public static final long DEFAULT_GLOBAL_SESSION_TIMEOUT = 30 * MILLIS_PER_MINUTE;

    private static final Logger log = LoggerFactory.getLogger(AbstractSessionManager.class);

    private long globalSessionTimeout = DEFAULT_GLOBAL_SESSION_TIMEOUT;
    private Collection<SessionListener> listeners = new ArrayList<SessionListener>();

    public AbstractSessionManager() {
    }

    /**
     * Returns the system-wide default time in milliseconds that any session may remain idle before expiring. This
     * value is the main default for all sessions and may be overridden on a <em>per-session</em> basis by calling
     * {@code Subject.getSession().}{@link Session#setTimeout setTimeout(long)} if so desired.
     * <ul>
     * <li>A negative return value means sessions never expire.</li>
     * <li>A non-negative return value (0 or greater) means session timeout will occur as expected.</li>
     * </ul>
     * <p/>
     * Unless overridden via the {@link #setGlobalSessionTimeout} method, the default value is
     * {@link #DEFAULT_GLOBAL_SESSION_TIMEOUT}.
     *
     * @return the time in milliseconds that any session may remain idle before expiring.
     */
    public long getGlobalSessionTimeout() {
        return this.globalSessionTimeout;
    }

    /**
     * Sets the system-wide default time in milliseconds that any session may remain idle before expiring. This
     * value is the main default for all sessions and may be overridden on a <em>per-session</em> basis by calling
     * {@code Subject.getSession().}{@link Session#setTimeout setTimeout(long)} if so desired.
     * <p/>
     * <ul>
     * <li>A negative return value means sessions never expire.</li>
     * <li>A non-negative return value (0 or greater) means session timeout will occur as expected.</li>
     * </ul>
     * <p/>
     * Unless overridden by calling this method, the default value is {@link #DEFAULT_GLOBAL_SESSION_TIMEOUT}.
     *
     * @param globalSessionTimeout the time in milliseconds that any session may remain idel before expiring.
     */
    public void setGlobalSessionTimeout(long globalSessionTimeout) {
        this.globalSessionTimeout = globalSessionTimeout;
    }

    public void setSessionListeners(Collection<SessionListener> listeners) {
        this.listeners = listeners != null ? listeners : new ArrayList<SessionListener>();
    }

    public void add(SessionListener listener) {
        this.listeners.add(listener);
    }

    public boolean remove(SessionListener listener) {
        return this.listeners.remove(listener);
    }

    public Serializable start(String host) throws AuthorizationException {
        Map<String, String> initData = null;
        if (StringUtils.hasText(host)) {
            initData = new HashMap<String, String>();
            initData.put(SessionFactory.HOST_KEY, host);
        }
        return start(initData);
    }

    public Serializable start(Map initData) throws AuthorizationException {
        Session session = createSession(initData);
        applyGlobalSessionTimeout(session);
        onStart(session);
        notifyStart(session);
        return session.getId();
    }

    protected void applyGlobalSessionTimeout(Session session) {
        session.setTimeout(getGlobalSessionTimeout());
        onChange(session);
    }

    /**
     * Returns the session instance to use to pass to registered {@code SessionListener}s for notification
     * that the session has been invalidated (stopped or expired).
     * <p/>
     * The default implementation returns an {@link ImmutableProxiedSession ImmutableProxiedSession} instance to ensure
     * that the specified {@code session} argument is not modified by any listeners.
     *
     * @param session the {@code Session} object being invalidated.
     * @return the {@code Session} instance to use to pass to registered {@code SessionListener}s for notification.
     */
    protected Session beforeInvalidNotification(Session session) {
        return new ImmutableProxiedSession(session);
    }

    /**
     * Notifies any interested {@link SessionListener}s that a Session has started.  This method is invoked
     * <em>after</em> the {@link #onStart(org.apache.shiro.session.Session)} method is called.
     *
     * @param session the session that has just started that will be delivered to any
     *                {@link #setSessionListeners(java.util.Collection) registered} session listeners.
     * @see SessionListener#onStart(org.apache.shiro.session.Session)
     */
    protected void notifyStart(Session session) {
        for (SessionListener listener : this.listeners) {
            listener.onStart(session);
        }
    }

    protected void notifyStop(Session session) {
        Session forNotification = beforeInvalidNotification(session);
        for (SessionListener listener : this.listeners) {
            listener.onStop(forNotification);
        }
    }

    protected void notifyExpiration(Session session) {
        Session forNotification = beforeInvalidNotification(session);
        for (SessionListener listener : this.listeners) {
            listener.onExpiration(forNotification);
        }
    }

    public Date getStartTimestamp(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public Date getLastAccessTime(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public long getTimeout(Serializable sessionId) throws InvalidSessionException {
        return getSession(sessionId).getTimeout();
    }

    public void setTimeout(Serializable sessionId, long maxIdleTimeInMillis) throws InvalidSessionException {
        Session s = getSession(sessionId);
        s.setTimeout(maxIdleTimeInMillis);
        onChange(s);
    }

    public void touch(Serializable sessionId) throws InvalidSessionException {
        Session s = getSession(sessionId);
        s.touch();
        onChange(s);
    }

    public String getHost(Serializable sessionId) {
        return getSession(sessionId).getHost();
    }

    public void stop(Serializable sessionId) throws InvalidSessionException {
        Session session = getSession(sessionId);
        stop(session);
    }

    protected void stop(Session session) {
        if (log.isDebugEnabled()) {
            log.debug("Stopping session with id [" + session.getId() + "]");
        }
        session.stop();
        onStop(session);
        notifyStop(session);
        afterStopped(session);
    }

    protected void afterStopped(Session session) {
    }

    public Collection<Object> getAttributeKeys(Serializable sessionId) {
        return getSession(sessionId).getAttributeKeys();
    }

    public Object getAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return getSession(sessionId).getAttribute(key);
    }

    public void setAttribute(Serializable sessionId, Object key, Object value) throws InvalidSessionException {
        if (value == null) {
            removeAttribute(sessionId, key);
        } else {
            Session s = getSession(sessionId);
            s.setAttribute(key, value);
            onChange(s);
        }
    }

    public Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        Session s = getSession(sessionId);
        Object removed = s.removeAttribute(key);
        if (removed != null) {
            onChange(s);
        }
        return removed;
    }

    protected Session getSession(Serializable sessionId) throws InvalidSessionException {
        if (sessionId == null) {
            throw new IllegalArgumentException("sessionId parameter cannot be null.");
        }
        Session session = doGetSession(sessionId);
        if (session == null) {
            String msg = "There is no session with id [" + sessionId + "]";
            throw new UnknownSessionException(msg);
        }
        return session;
    }

    public boolean isValid(Serializable sessionId) {
        try {
            checkValid(sessionId);
            return true;
        } catch (InvalidSessionException e) {
            return false;
        }
    }

    public void checkValid(Serializable sessionId) throws InvalidSessionException {
        //just try to acquire it.  If there is a problem, an exception will be thrown:
        getSession(sessionId);
    }

    /**
     * Template method that allows subclasses to react to a new session being created.
     * <p/>
     * This method is invoked <em>before</em> any session listeners are notified.
     *
     * @param session the session that was just {@link #createSession created}.
     */
    protected void onStart(Session session) {
    }

    protected void onStop(Session session) {
        onChange(session);
    }

    protected void onChange(Session s) {
    }

    protected abstract Session doGetSession(Serializable sessionId) throws InvalidSessionException;

    /**
     * Creates a new {@code Session Session} instance based on the specified (possibly {@code null})
     * initialization data.  Implementing classes must manage the persistent state of the returned session such that it
     * could later be acquired via the {@link #getSession(java.io.Serializable)} method.
     *
     * @param initData the initialization data that can be used by the implementation or underlying
     *                 {@link SessionFactory} when instantiating the internal {@code Session} instance.
     * @return the new {@code Session} instance.
     * @throws HostUnauthorizedException if the system access control policy restricts access based
     *                                   on client location/IP and the specified hostAddress hasn't been enabled.
     * @throws AuthorizationException    if the system access control policy does not allow the currently executing
     *                                   caller to start sessions.
     */
    protected abstract Session createSession(Map initData) throws AuthorizationException;
}
