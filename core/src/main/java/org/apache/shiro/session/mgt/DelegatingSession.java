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
import java.util.Collection;
import java.util.Date;

/**
 * A DelegatingSession is a client-tier representation of a server side
 * {@link org.apache.shiro.session.Session Session}.
 * This implementation is basically a proxy to a server-side {@link NativeSessionManager NativeSessionManager},
 * which will return the proper results for each method call.
 * <p/>
 * <p>A <tt>DelegatingSession</tt> will cache data when appropriate to avoid a remote method invocation,
 * only communicating with the server when necessary.
 * <p/>
 * <p>Of course, if used in-process with a NativeSessionManager business POJO, as might be the case in a
 * web-based application where the web classes and server-side business pojos exist in the same
 * JVM, a remote method call will not be incurred.
 *
 * @since 0.1
 */
public class DelegatingSession implements Session, Serializable {

    //TODO - complete JavaDoc

    private final SessionKey key;

    //cached fields to avoid a server-side method call if out-of-process:
    private Date startTimestamp = null;
    private String host = null;

    /**
     * Handle to the target NativeSessionManager that will support the delegate calls.
     */
    private final transient NativeSessionManager sessionManager;


    public DelegatingSession(NativeSessionManager sessionManager, SessionKey key) {
        if (sessionManager == null) {
            throw new IllegalArgumentException("sessionManager argument cannot be null.");
        }
        if (key == null) {
            throw new IllegalArgumentException("sessionKey argument cannot be null.");
        }
        if (key.getSessionId() == null) {
            String msg = "The " + DelegatingSession.class.getName() + " implementation requires that the " +
                    "SessionKey argument returns a non-null sessionId to support the " +
                    "Session.getId() invocations.";
            throw new IllegalArgumentException(msg);
        }
        this.sessionManager = sessionManager;
        this.key = key;
    }

    /**
     * @see org.apache.shiro.session.Session#getId()
     */
    public Serializable getId() {
        return key.getSessionId();
    }

    /**
     * @see org.apache.shiro.session.Session#getStartTimestamp()
     */
    public Date getStartTimestamp() {
        if (startTimestamp == null) {
            startTimestamp = sessionManager.getStartTimestamp(key);
        }
        return startTimestamp;
    }

    /**
     * @see org.apache.shiro.session.Session#getLastAccessTime()
     */
    public Date getLastAccessTime() {
        //can't cache - only business pojo knows the accurate time:
        return sessionManager.getLastAccessTime(key);
    }

    public long getTimeout() throws InvalidSessionException {
        return sessionManager.getTimeout(key);
    }

    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        sessionManager.setTimeout(key, maxIdleTimeInMillis);
    }

    public String getHost() {
        if (host == null) {
            host = sessionManager.getHost(key);
        }
        return host;
    }

    /**
     * @see org.apache.shiro.session.Session#touch()
     */
    public void touch() throws InvalidSessionException {
        sessionManager.touch(key);
    }

    /**
     * @see org.apache.shiro.session.Session#stop()
     */
    public void stop() throws InvalidSessionException {
        sessionManager.stop(key);
    }

    /**
     * @see org.apache.shiro.session.Session#getAttributeKeys
     */
    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return sessionManager.getAttributeKeys(key);
    }

    /**
     * @see org.apache.shiro.session.Session#getAttribute(Object key)
     */
    public Object getAttribute(Object attributeKey) throws InvalidSessionException {
        return sessionManager.getAttribute(this.key, attributeKey);
    }

    /**
     * @see Session#setAttribute(Object key, Object value)
     */
    public void setAttribute(Object attributeKey, Object value) throws InvalidSessionException {
        if (value == null) {
            removeAttribute(attributeKey);
        } else {
            sessionManager.setAttribute(this.key, attributeKey, value);
        }
    }

    /**
     * @see Session#removeAttribute(Object key)
     */
    public Object removeAttribute(Object attributeKey) throws InvalidSessionException {
        return sessionManager.removeAttribute(this.key, attributeKey);
    }
}
