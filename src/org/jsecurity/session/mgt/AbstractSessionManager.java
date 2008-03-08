/*
 * Copyright (C) 2005-2007 Les Hazlewood
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
package org.jsecurity.session.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
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
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public abstract class AbstractSessionManager implements SessionManager, CacheProviderAware, SessionEventListenerRegistrar {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected SessionEventManager sessionEventManager = new DefaultSessionEventManager();
    protected CacheProvider cacheProvider;

    public AbstractSessionManager() {
    }

    public SessionEventManager getSessionEventManager() {
        return sessionEventManager;
    }

    public void setSessionEventManager(SessionEventManager sessionEventManager) {
        this.sessionEventManager = sessionEventManager;
    }

    public CacheProvider getCacheProvider() {
        return cacheProvider;
    }

    public void setCacheProvider(CacheProvider cacheProvider) {
        this.cacheProvider = cacheProvider;
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
