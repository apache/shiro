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
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.cache.CacheProvider;
import org.jsecurity.cache.CacheProviderAware;
import org.jsecurity.session.*;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.mgt.SessionEventListenerRegistrar;
import org.jsecurity.util.Destroyable;
import org.jsecurity.util.Initializable;
import org.jsecurity.util.LifecycleUtils;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;

/**
 * Default JSecurity implementation of a {@link org.jsecurity.session.SessionFactory} that relies on an internally
 * wrapped {@link SessionManager SessionManager} to perform all session operations.
 *
 * <p>The <tt>Session</tt> instances returned from this implementation are lightweight proxies that delegate
 * their method calls to the aforementioned <tt>SessionManager</tt> that manages all the Sessions in the system.
 *
 * <p>This transparent proxy/delegate technique allows the JSecurity support classes to
 * maintain a stateless architecture (similar to accessing a EJB Stateless Session Bean),
 * which is extremely efficient.  Any state to be maintained is the responsibility of the
 * SessionManager, not the Session implementation, enabling cleaner and more efficient code and business-tier
 * caching strategies for efficient data management.
 *
 * <p>Also because of this stateless proxying technique, <tt>Session</tt> instances returned from this factory
 * implementation are extremely lightweight and are designed to be instantiated as needed.  They should not be cached
 * long-term in the business/server tier (e.g. in an <tt>HttpSession</tt> or in some class {@link java.util.Map Map}
 * attribute), since they can just be recreated upon each request to the system or method chain invocation.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class DefaultSessionFactory implements SessionFactory, SessionEventListenerRegistrar, CacheProviderAware, Initializable, Destroyable {

    protected final transient Log log = LogFactory.getLog(getClass());

    protected SessionManager sessionManager = null;
    protected Collection<SessionEventListener> sessionEventListeners = null;
    protected CacheProvider cacheProvider;

    public DefaultSessionFactory() {
    }

    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    public CacheProvider getCacheProvider() {
        return cacheProvider;
    }

    public void setCacheProvider(CacheProvider cacheProvider) {
        this.cacheProvider = cacheProvider;
    }

    private void assertSessionManagerEventNotifier() {
        if (!(this.sessionManager instanceof SessionEventListenerRegistrar)) {
            String msg = "The underlying SessionManager implementation [" +
                    this.sessionManager.getClass().getName() + "] does not implement the " +
                    SessionEventListenerRegistrar.class.getName() + " interface and therefore session events cannot " +
                    "be propagated to registered listeners.  Please ensure this SessionFactory instance is " +
                    "injected with a SessionManager that supports this interface if you wish to register " +
                    "for SessionEvents.";
            throw new IllegalStateException(msg);
        }
    }

    public void add(SessionEventListener listener) {
        assertSessionManagerEventNotifier();
        ((SessionEventListenerRegistrar)this.sessionManager).add(listener);
    }

    public boolean remove(SessionEventListener listener) {
        return this.sessionManager instanceof SessionEventListenerRegistrar &&
               ((SessionEventListenerRegistrar) this.sessionManager).remove(listener);
    }

    public void setSessionEventListeners(Collection<SessionEventListener> listeners) {
        this.sessionEventListeners = listeners;
    }

    protected SessionManager createSessionManager() {
        DefaultSessionManager sessionManager = new DefaultSessionManager();
        if ( getCacheProvider() != null ) {
            sessionManager.setCacheProvider( getCacheProvider() );
        }
        sessionManager.setSessionEventListeners(this.sessionEventListeners);
        sessionManager.init();
        return sessionManager;
    }

    protected void ensureSessionManager() {
        if (this.sessionManager == null) {
            if (log.isInfoEnabled()) {
                log.info("No SessionManager instance has been set as a property of this class.  " +
                        "Defaulting to the default SessionManager implementation.");
            }
            SessionManager sessionManager = createSessionManager();
            setSessionManager(sessionManager);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Using configured SessionManager [" + sessionManager + "] for SessionFactory support.");
            }
        }
    }

    public void init() {
        ensureSessionManager();
    }

    public void destroy() {
        LifecycleUtils.destroy(this.sessionManager);
        this.sessionManager = null;
    }

    public Session start(InetAddress hostAddress)
            throws HostUnauthorizedException, IllegalArgumentException {
        Serializable sessionId = sessionManager.start(hostAddress);
        return new DelegatingSession(sessionManager, sessionId);
    }

    public Session getSession(Serializable sessionId)
            throws InvalidSessionException, AuthorizationException {

        if (sessionManager.isExpired(sessionId)) {
            String msg = "Session with id [" + sessionId + "] has expired and may not " +
                    "be used.";
            throw new ExpiredSessionException(msg);
        } else if (sessionManager.isStopped(sessionId)) {
            String msg = "Session with id [" + sessionId + "] has been stopped and may not " +
                    "be used.";
            throw new StoppedSessionException(msg);
        }

        return new DelegatingSession(sessionManager, sessionId);
    }

}
