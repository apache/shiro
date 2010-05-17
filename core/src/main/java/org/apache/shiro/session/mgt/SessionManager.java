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
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.util.Collection;
import java.util.Date;

/**
 * A SessionManager manages the creation, maintenance, and clean-up of all application
 * {@link org.apache.shiro.session.Session Session}s.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public interface SessionManager {

    /**
     * Starts a new session based on the specified contextual initialization data, which can be used by the underlying
     * implementation to determine how exactly to create the internal Session instance.
     * <p/>
     * This method is mainly used in framework development, as the implementation will often relay the argument
     * to an underlying {@link SessionFactory} which could use the context to construct the internal Session
     * instance in a specific manner.  This allows pluggable {@link org.apache.shiro.session.Session Session} creation
     * logic by simply injecting a {@code SessionFactory} into the {@code SessionManager} instance.
     *
     * @param initData the contextual initialization data that can be used by the implementation or underlying
     *                 {@link SessionFactory} when instantiating the internal {@code Session} instance.
     * @return the newly created session.
     * @throws HostUnauthorizedException if the system access control policy restricts access based
     *                                   on client location/IP and the specified host address hasn't been enabled.
     * @throws AuthorizationException    if the system access control policy does not allow the currently executing
     *                                   caller to start sessions.
     * @see SessionFactory#createSession(SessionContext)
     * @since 1.0
     */
    Session start(SessionContext initData) throws AuthorizationException;

    /**
     * Returns the time the Session identified by the specified {@code sessionId} was started
     * in the system.
     *
     * @param sessionId the system identifier for the session of interest.
     * @return the system time the specified session was started (i.e. created).
     * @see org.apache.shiro.session.Session#getStartTimestamp()
     */
    Date getStartTimestamp(Serializable sessionId);

    /**
     * Returns the time the {@code Session} identified by the specified {@code sessionId} last
     * interacted with the system.
     *
     * @param sessionId the system identifier for the session of interest
     * @return time the session last accessed the system
     * @see org.apache.shiro.session.Session#getLastAccessTime()
     * @see org.apache.shiro.session.Session#touch()
     */
    Date getLastAccessTime(Serializable sessionId);

    /**
     * Returns {@code true} if the session is valid (it exists and is not stopped nor expired), {@code false} otherwise.
     *
     * @param sessionId the id of the session to check
     * @return {@code true} if the session is valid (exists and is not stopped or expired), {@code false} otherwise.
     */
    boolean isValid(Serializable sessionId);

    /**
     * Returns quietly if the associated session is valid (it exists and is not stopped or expired) or throws
     * an {@link InvalidSessionException} indicating that the session id is invalid.  This might be preferred to be
     * used instead of {@link #isValid} since any exception thrown will definitively explain the reason for
     * invalidation.
     *
     * @param sessionId the session id to check for validity.
     * @throws InvalidSessionException if the session id is invalid (it does not exist or it is stopped or expired).
     * @since 1.0
     */
    void checkValid(Serializable sessionId) throws InvalidSessionException;

    /**
     * Returns the time in milliseconds that the specified session may remain idle before expiring.
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param sessionId the system identifier of the session of interest.
     * @return the time in milliseconds that the specified session may remain idle before expiring.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @since 0.2
     */
    long getTimeout(Serializable sessionId) throws InvalidSessionException;

    /**
     * Sets the time in milliseconds that the specified session may remain idle before expiring.
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param sessionId           the system identifier of the session of interest.
     * @param maxIdleTimeInMillis the time in milliseconds that the specified session may remain idle before expiring.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @since 0.2
     */
    void setTimeout(Serializable sessionId, long maxIdleTimeInMillis) throws InvalidSessionException;

    /**
     * Updates the last accessed time of the session identified by <code>sessionId</code>.  This
     * can be used to explicitly ensure that a session does not time out.
     *
     * @param sessionId the id of the session to update.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#touch
     */
    void touch(Serializable sessionId) throws InvalidSessionException;

    /**
     * Returns the host name or IP string of the host where the session was started, if known.  If
     * no host name or IP was specified when starting the session, this method returns {@code null}
     *
     * @param sessionId the id of the session to query.
     * @return the host name or ip address of the host where the session originated, if known.  If unknown,
     *         this method returns {@code null}.
     * @since 1.0
     */
    String getHost(Serializable sessionId);

    /**
     * Explicitly stops the session identified by {@code sessionId}, thereby releasing all
     * associated resources.
     *
     * @param sessionId the system identfier of the system to destroy.
     * @throws InvalidSessionException if the session has stopped or expired prior to calling
     *                                 this method.
     * @see org.apache.shiro.session.Session#stop
     */
    void stop(Serializable sessionId) throws InvalidSessionException;

    /**
     * Returns the keys of all the attributes stored under the session identified by {@code sessionId}.
     * If there are no attributes, this returns an empty collection.
     *
     * @param sessionId the system identifier of the system to access.
     * @return the keys of all attributes stored under the specified session, or an empty collection if
     *         there are no session attributes.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#getAttributeKeys()
     * @since 0.2
     */
    Collection<Object> getAttributeKeys(Serializable sessionId);

    /**
     * Returns the object bound to the specified session identified by the specified key.  If there
     * is noobject bound under the key for the given session, {@code null} is returned.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key       the unique name of the object bound to the specified session
     * @return the object bound under the specified {@code key} name or {@code null} if there is
     *         no object bound under that name.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#getAttribute(Object key)
     */
    Object getAttribute(Serializable sessionId, Object key) throws InvalidSessionException;

    /**
     * Binds the specified {@code value} to the specified session uniquely identified by the
     * specifed {@code key} name.  If there is already an object bound under the {@code key}
     * name, that existing object will be replaced by the new {@code value}.
     * <p/>
     * If the {@code value} parameter is null, it has the same effect as if the
     * {@link #removeAttribute(Serializable sessionId, Object key)} method was called.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key       the name under which the {@code value} object will be bound in this session
     * @param value     the object to bind in this session.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#setAttribute(Object key, Object value)
     */
    void setAttribute(Serializable sessionId, Object key, Object value) throws InvalidSessionException;

    /**
     * Removes (unbinds) the object bound to this session under the specified {@code key} name.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key       the name uniquely identifying the object to remove
     * @return the object removed or {@code null} if there was no object bound under the specified
     *         {@code key} name.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#removeAttribute(Object key)
     */
    Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException;
}
