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
package org.jsecurity.session.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.cache.CacheManager;
import org.jsecurity.cache.CacheManagerAware;
import org.jsecurity.session.ExpiredSessionException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.UnknownSessionException;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.mgt.DefaultSessionEventManager;
import org.jsecurity.session.event.mgt.SessionEventListenerRegistrar;
import org.jsecurity.session.event.mgt.SessionEventManager;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AbstractSessionManager implements SessionManager, CacheManagerAware, SessionEventListenerRegistrar {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected SessionEventManager sessionEventManager = new DefaultSessionEventManager();
    protected CacheManager cacheManager;

    public AbstractSessionManager() {
    }

    public SessionEventManager getSessionEventManager() {
        return sessionEventManager;
    }

    public void setSessionEventManager(SessionEventManager sessionEventManager) {
        this.sessionEventManager = sessionEventManager;
    }

    public CacheManager getCacheManager() {
        return cacheManager;
    }

    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public void setSessionEventListeners(Collection<SessionEventListener> listeners) {
        this.sessionEventManager.setSessionEventListeners(listeners);
    }

    public void add(SessionEventListener listener) {
        this.sessionEventManager.add(listener);
    }

    public boolean remove(SessionEventListener listener) {
        return this.sessionEventManager.remove(listener);
    }

    public Serializable start(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        Session session = createSession(originatingHost);
        sendStartEvent(session);
        return session.getId();
    }

    protected void sendStartEvent(Session session) {
        this.sessionEventManager.sendStartEvent(session);
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
        sendStopEvent(session);
        session.stop();
        onStop(session);
    }

    protected void sendStopEvent(Session session) {
        this.sessionEventManager.sendStopEvent(session);
    }

    protected void onStop(Session session) {
        onChange(session);
    }

    protected void expire(Session session) {
        if (log.isDebugEnabled()) {
            log.debug("Expiring session with id [" + session.getId() + "]");
        }
        sendExpirationEvent(session);
        session.stop();
        onExpiration(session);
    }

    protected void sendExpirationEvent(Session session) {
        this.sessionEventManager.sendExpirationEvent(session);
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
        if ( value == null ) {
            removeAttribute(sessionId,key);
        } else {
            Session s = getSession(sessionId);
            s.setAttribute(key, value);
            onChange(s);
        }
    }

    public Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        Session s = getSession(sessionId);
        Object removed = s.removeAttribute(key);
        if ( removed != null ) {
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

    protected void onChange( Session s ){}

    protected abstract Session doGetSession(Serializable sessionId) throws InvalidSessionException;

    protected abstract Session createSession(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException;
}
