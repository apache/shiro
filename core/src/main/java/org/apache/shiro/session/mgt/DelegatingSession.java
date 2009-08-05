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

import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * A DelegatingSession is a client-tier representation of a server side
 * {@link org.apache.shiro.session.Session Session}.
 * This implementation is basically a proxy to a server-side {@link SessionManager SessionManager},
 * which will return the proper results for each method call.
 * <p/>
 * <p>A <tt>DelegatingSession</tt> will cache data when appropriate to avoid a remote method invocation,
 * only communicating with the server when necessary.
 * <p/>
 * <p>Of course, if used in-process with a SessionManager business POJO, as might be the case in a
 * web-based application where the web classes and server-side business pojos exist in the same
 * JVM, a remote method call will not be incurred.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.1
 */
public class DelegatingSession implements Session, Serializable {

    //TODO - complete JavaDoc

    private Serializable id = null;

    //cached fields to avoid a server-side method call if out-of-process:
    private Date startTimestamp = null;
    private InetAddress hostAddress = null;

    /**
     * Handle to a server-side SessionManager.  See {@link #setSessionManager} for details.
     */
    private transient SessionManager sessionManager = null;


    public DelegatingSession() {
    }

    public DelegatingSession(SessionManager sessionManager, Serializable id) {
        if (sessionManager == null) {
            throw new IllegalArgumentException("sessionManager argument cannot be null.");
        }
        if (id == null) {
            throw new IllegalArgumentException("session id argument cannot be null.");
        }
        this.sessionManager = sessionManager;
        this.id = id;
    }

    public DelegatingSession(SessionManager sessionManager, Serializable id, InetAddress hostAddress) {
        this(sessionManager, id);
        this.hostAddress = hostAddress;
    }

    /**
     * Returns the {@link SessionManager SessionManager} used by this handle to invoke
     * all session-related methods.
     *
     * @return the {@link SessionManager SessionManager} used by this handle to invoke
     *         all session-related methods.
     */
    public SessionManager getSessionManager() {
        return sessionManager;
    }

    /**
     * Sets the {@link SessionManager SessionManager} to which this <tt>DelegatingSession</tt> will
     * delegate its method calls.  In a rich client environment, this <tt>SessionManager</tt> will
     * probably be a remoting proxy which executes remote method invocations.  In a single-process
     * environment (e.g. a web  application deployed in the same JVM of the application server),
     * the <tt>SessionManager</tt> can be the actual business POJO implementation.
     * <p/>
     * <p>You'll notice the {@link Session Session} interface and the {@link SessionManager}
     * interface are nearly identical.  This is to ensure the SessionManager can support
     * most method calls in the Session interface, via this handle/proxy technique.  The session
     * manager is implementated as a stateless business POJO, with the handle passing the
     * session id as necessary.
     *
     * @param sessionManager the <tt>SessionManager</tt> this handle will use when delegating
     *                       method calls.
     */
    public void setSessionManager(SessionManager sessionManager) {
        this.sessionManager = sessionManager;
    }

    /**
     * Sets the sessionId used by this handle for all future {@link SessionManager SessionManager}
     * method invocations.
     *
     * @param id the <tt>sessionId</tt> to use for all <tt>SessionManager</tt> invocations.
     * @see #setSessionManager(SessionManager sessionManager)
     */
    public void setId(Serializable id) {
        this.id = id;
    }

    /**
     * @see org.apache.shiro.session.Session#getId()
     */
    public Serializable getId() {
        return id;
    }

    /**
     * @see org.apache.shiro.session.Session#getStartTimestamp()
     */
    public Date getStartTimestamp() {
        if (startTimestamp == null) {
            startTimestamp = sessionManager.getStartTimestamp(id);
        }
        return startTimestamp;
    }

    /**
     * @see org.apache.shiro.session.Session#getLastAccessTime()
     */
    public Date getLastAccessTime() {
        //can't cache - only business pojo knows the accurate time:
        return sessionManager.getLastAccessTime(id);
    }

    public long getTimeout() throws InvalidSessionException {
        return sessionManager.getTimeout(id);
    }

    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        sessionManager.setTimeout(id, maxIdleTimeInMillis);
    }

    /**
     * @see org.apache.shiro.session.Session#getHostAddress()
     */
    public InetAddress getHostAddress() {
        if (hostAddress == null) {
            hostAddress = sessionManager.getHostAddress(id);
        }
        return hostAddress;
    }

    /**
     * @see org.apache.shiro.session.Session#touch()
     */
    public void touch() throws InvalidSessionException {
        sessionManager.touch(id);
    }

    /**
     * @see org.apache.shiro.session.Session#stop()
     */
    public void stop() throws InvalidSessionException {
        sessionManager.stop(id);
    }

    /**
     * @see org.apache.shiro.session.Session#getAttributeKeys
     */
    @SuppressWarnings({"unchecked"})
    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return sessionManager.getAttributeKeys(id);
    }

    /**
     * @see org.apache.shiro.session.Session#getAttribute(Object key)
     */
    public Object getAttribute(Object key) throws InvalidSessionException {
        return sessionManager.getAttribute(id, key);
    }

    /**
     * @see Session#setAttribute(Object key, Object value)
     */
    public void setAttribute(Object key, Object value) throws InvalidSessionException {
        if (value == null) {
            removeAttribute(key);
        } else {
            sessionManager.setAttribute(id, key, value);
        }
    }

    /**
     * @see Session#removeAttribute(Object key)
     */
    public Object removeAttribute(Object key) throws InvalidSessionException {
        return sessionManager.removeAttribute(id, key);
    }
}
