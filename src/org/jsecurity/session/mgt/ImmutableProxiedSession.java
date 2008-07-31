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

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * Implementation of the {@link Session Session} interface that proxies another <code>Session</code>, but does not
 * allow any write operations to the underlying session. It allows read-only operations only.
 * <p/>
 * The <code>Session</code> write operations are defined as follows.  A call to any of these methods on this
 * proxy will immediately result in an {@link InvalidSessionException} being thrown:
 *
 * <ul>
 * <li>{@link Session#setTimeout(long) Session.setTimeout(long)}</li>
 * <li>{@link Session#touch() Session.touch()}</li>
 * <li>{@link Session#stop() Session.stop()}</li>
 * <li>{@link Session#setAttribute(Object, Object) Session.setAttribute(key,value)}</li>
 * <li>{@link Session#removeAttribute(Object) Session.removeAttribute(key)}</li>
 * </ul>
 *
 * <p/>
 * Any other method invocation not listed above will result in a corresponding call to the underlying <code>Session</code>.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class ImmutableProxiedSession implements Session {

    /**
     * The proxied Session
     */
    protected final Session session;

    /**
     * Constructs a new instance of this class proxying the specified <code>Session</code>.
     *
     * @param toProxy the <code>Session</code> to proxy.
     */
    public ImmutableProxiedSession(Session toProxy) {
        this.session = toProxy;
        if (toProxy == null) {
            throw new IllegalArgumentException("Session to proxy cannot be null.");
        }
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return The unique identifier assigned to the session upon creation.
     */
    public Serializable getId() {
        return this.session.getId();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return The time the system created the session.
     */
    public Date getStartTimestamp() {
        return this.session.getStartTimestamp();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return The time the session was stopped, or <tt>null</tt> if the session is still
     *         active.
     */
    public Date getStopTimestamp() {
        return this.session.getStopTimestamp();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return The time the user last interacted with the system.
     */
    public Date getLastAccessTime() {
        return this.session.getLastAccessTime();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return true if this session has expired, false otherwise.
     */
    public boolean isExpired() {
        return this.session.isExpired();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return the time in milliseconds the session may remain idle before expiring.
     * @throws InvalidSessionException
     */
    public long getTimeout() throws InvalidSessionException {
        return this.session.getTimeout();
    }

    /**
     * Simply throws an <code>InvalidSessionException</code> indicating that this proxy is immutable.  Used
     * only in the Session's 'write' methods documented in the top class-level JavaDoc.
     *
     * @throws InvalidSessionException in all cases - used by the Session 'write' method implementations.
     */
    protected void throwImmutableException() throws InvalidSessionException {
        String msg = "This session is immutable and read-only - it cannot be altered.  This is usually because " +
                "the session has been stopped or expired already.";
        throw new InvalidSessionException(msg);
    }

    /**
     * Immediately {@link #throwImmutableException() throws} an <code>InvalidSessionException</code> in all
     * cases because this proxy is immutable.
     *
     * @param maxIdleTimeInMillis ignored
     * @throws InvalidSessionException in all cases because this proxy is immutable.
     */
    public void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException {
        throwImmutableException();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return the <tt>InetAddress</tt> of the host that originated this session, or <tt>null</tt>
     *         if the host address is unknown.
     */
    public InetAddress getHostAddress() {
        return this.session.getHostAddress();
    }

    /**
     * Immediately {@link #throwImmutableException() throws} an <code>InvalidSessionException</code> in all
     * cases because this proxy is immutable.
     *
     * @throws InvalidSessionException in all cases because this proxy is immutable.
     */
    public void touch() throws InvalidSessionException {
        throwImmutableException();
    }

    /**
     * Immediately {@link #throwImmutableException() throws} an <code>InvalidSessionException</code> in all
     * cases because this proxy is immutable.
     *
     * @throws InvalidSessionException in all cases because this proxy is immutable.
     */
    public void stop() throws InvalidSessionException {
        throwImmutableException();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     *
     * @return the keys of all attributes stored under this session, or an empty collection if
     *         there are no session attributes.
     */
    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return this.session.getAttributeKeys();
    }

    /**
     * Immediately delegates to the underlying proxied session.
     * param key the unique name of the object bound to this session
     *
     * @return the object bound under the specified <tt>key</tt> name or <tt>null</tt> if there is
     *         no object bound under that name.
     * @throws InvalidSessionException
     */
    public Object getAttribute(Object key) throws InvalidSessionException {
        return this.session.getAttribute(key);
    }

    /**
     * Immediately {@link #throwImmutableException() throws} an <code>InvalidSessionException</code> in all
     * cases because this proxy is immutable.
     *
     * @param key   ignored
     * @param value ignored
     * @throws InvalidSessionException in all cases because this proxy is immutable.
     */
    public void setAttribute(Object key, Object value) throws InvalidSessionException {
        throwImmutableException();
    }

    /**
     * Immediately {@link #throwImmutableException() throws} an <code>InvalidSessionException</code> in all
     * cases because this proxy is immutable.
     *
     * @param key ignored
     * @throws InvalidSessionException in all cases because this proxy is immutable.
     */
    public Object removeAttribute(Object key) throws InvalidSessionException {
        throwImmutableException();
        //we should never ever reach this point due to the exception being thrown.
        throw new InternalError("This code should never execute - please report this as a bug!");
    }
}
