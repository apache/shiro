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
package org.jsecurity.session.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.*;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

/**
 * @author Les Hazlewood
 * @since 0.1
 */
public abstract class AbstractSessionManager implements SessionManager, SessionListenerRegistrar {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected Collection<SessionListener> listeners = new ArrayList<SessionListener>();

    public AbstractSessionManager() {
    }

    public void setSessionListeners(Collection<SessionListener> listeners) {
        if (listeners == null) {
            this.listeners = new ArrayList<SessionListener>();
        } else {
            this.listeners = listeners;
        }
    }

    public void add(SessionListener listener) {
        this.listeners.add(listener);
    }

    public boolean remove(SessionListener listener) {
        return this.listeners.remove(listener);
    }

    public Serializable start(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        Session session = createSession(originatingHost);
        notifyStart(session);
        return session.getId();
    }

    /**
     * Returns the session instance to use to pass to registered <code>SessionListener</code>s for notification
     * that the session has been validated (stopped or expired).
     * <p/>
     * The default implementation returns an
     * {@link org.jsecurity.session.mgt.ImmutableProxiedSession ImmutableProxiedSession} instance to ensure
     * that the specified <code>session</code> argument is not modified by any listeners.
     *
     * @param session the <code>Session</code> object being invalidated.
     * @return the <code>Session</code> instance to use to pass to registered <code>SessionListener</code>s for
     *         notification.
     */
    protected Session beforeInvalidNotification(Session session) {
        return new ImmutableProxiedSession(session);
    }

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

    public Date getStopTimestamp(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public Date getLastAccessTime(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public boolean isStopped(Serializable sessionId) {
        Session session = getSession(sessionId);
        return session.getStopTimestamp() != null || session.isExpired();
    }

    public boolean isExpired(Serializable sessionId) {
        try {
            Session session = getSession(sessionId);
            return session.isExpired();
        } catch (ExpiredSessionException e) {
            return true;
        }
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

    public InetAddress getHostAddress(Serializable sessionId) {
        return getSession(sessionId).getHostAddress();
    }

    public void stop(Serializable sessionId) throws InvalidSessionException {
        Session session = getSession(sessionId);
        stop(session);
    }

    protected void stop(Session session) {
        if (log.isDebugEnabled()) {
            log.debug("Stopping session with id [" + session.getId() + "]");
        }
        notifyStop(session);
        session.stop();
        onStop(session);
    }

    protected void onStop(Session session) {
        onChange(session);
    }

    protected void expire(Session session) {
        if (log.isDebugEnabled()) {
            log.debug("Expiring session with id [" + session.getId() + "]");
        }
        notifyExpiration(session);
        session.stop();
        onExpiration(session);
    }

    protected void onExpiration(Session session) {
        onChange(session);
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
        Session session = doGetSession(sessionId);
        if (session == null) {
            String msg = "There is no session with id [" + sessionId + "]";
            throw new UnknownSessionException(msg);
        }
        return session;
    }

    protected void onChange(Session s) {
    }

    protected abstract Session doGetSession(Serializable sessionId) throws InvalidSessionException;

    protected abstract Session createSession(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException;
}
