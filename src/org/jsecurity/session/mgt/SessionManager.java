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

import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * A SessionManager manages the creation, maintenance, and clean-up of all application
 * {@link org.jsecurity.session.Session Session}s.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public interface SessionManager {

    /**
     * Starts a new session within the system for the host with the specified originating IP
     * address.
     *
     * <p><b>Note</b>: see the
     * {@link org.jsecurity.session.SessionFactory#start(java.net.InetAddress) SessionFactory.init(InetAddress)} method
     * about the implications of using <tt>InetAddress</tt>es in access control policies.
     *
     * @param originatingHost the originating host InetAddress of the external party
     *                        (user, 3rd party product, etc) that is attempting to interact with the system.
     * @return the system identifier of the newly created session.
     * @throws IllegalArgumentException if the host specified is not valid.
     * @throws org.jsecurity.authz.HostUnauthorizedException
     *                                  if the host specified is not allowed to start sessions.
     * @see org.jsecurity.session.SessionFactory#start(InetAddress)
     */
    Serializable start(InetAddress originatingHost)
            throws HostUnauthorizedException, IllegalArgumentException;

    /**
     * Returns the time the Session identified by the specified <tt>sessionId</tt> was started
     * in the system.
     *
     * @param sessionId the system identifier for the session of interest.
     * @return the system time the specified session was started (i.e. created).
     * @see org.jsecurity.session.Session#getStartTimestamp()
     */
    Date getStartTimestamp(Serializable sessionId);

    /**
     * Returns the time the <tt>Session</tt> identified by the specified <tt>sessionId</tt> was
     * stopped or expired in the system, or <tt>null</tt> if the session is still active. A
     * session could be stopped for a number of reasons.  See the
     * {@link org.jsecurity.session.Session#stop() Session.destroy()} method for more details.
     *
     * @param sessionId the session ID whose stop timestamp is being retrieved.
     * @return the system time the session stopped or expired, or <tt>null</tt> if the session
     *         is still active.
     * @see org.jsecurity.session.Session#getStopTimestamp()
     */
    Date getStopTimestamp(Serializable sessionId);

    /**
     * Returns the time the <tt>Session</tt> identified by the specified <tt>sessionId</tt> last
     * interacted with the system.
     *
     * @param sessionId the system identifier for the session of interest
     * @return tye time the session last accessed the system
     * @see org.jsecurity.session.Session#getLastAccessTime()
     * @see org.jsecurity.session.Session#touch()
     */
    Date getLastAccessTime(Serializable sessionId);

    /**
     * Returns <tt>true</tt> if the session with the specified <tt>sessionId</tt> has been
     * stopped, <tt>false</tt> otherwise.
     *
     * @param sessionId the id of the session to check
     * @return <tt>true</tt> if the session has been stopped, <tt>false</tt> otherwise.
     */
    boolean isStopped(Serializable sessionId);

    /**
     * Returns whether or not the session identified by the given <tt>sessionId</tt> has expired
     * in the system.
     *
     * <p>This method can be used in conjunction with {@link #isStopped} to determine if the
     * user has logged out, depending upon an application's inference of business rules.
     * Assuming the only way for a session to be stopped (other than from
     * expiration) is due to an explicit user log-out you can infer that if the session
     * {@link #isStopped} but not {@link #isExpired}, then the user has logged-out.  Of course,
     * this is dependent upon the above assumption and may not be true for every application.
     *
     * @param sessionId the system identifier of the session of interest
     * @return true if the session has expired, false otherwise.
     */
    boolean isExpired(Serializable sessionId);

    /**
     * Returns the time in milliseconds that the specified session may remain idle before expiring.
     *
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param sessionId the system identifier of the session of interest.
     * @return the time in milliseconds that the specified session may remain idle before expiring.
     * @throws org.jsecurity.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @since 0.2
     */
    long getTimeout(Serializable sessionId) throws InvalidSessionException;

    /**
     * Sets the time in milliseconds that the specified session may remain idle before expiring.
     *
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param sessionId           the system identifier of the session of interest.
     * @param maxIdleTimeInMillis the time in milliseconds that the specified session may remain idle before expiring.
     * @throws org.jsecurity.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @since 0.2
     */
    void setTimeout(Serializable sessionId, long maxIdleTimeInMillis) throws InvalidSessionException;

    /**
     * Updates the last accessed time of the session identified by <code>sessionId</code>.  This
     * can be used to explicitly ensure that a session does not time out.
     *
     * @param sessionId the id of the session to update.
     * @throws org.jsecurity.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#touch
     */
    void touch(Serializable sessionId) throws InvalidSessionException;


    /**
     * Returns the IP address of the host where the session was started, if known.  If
     * no IP was specified when starting the session, this method returns <code>null</code>
     *
     * @param sessionId the id of the session to query.
     * @return the ip address of the host where the session originated, if known.  If unknown,
     *         this method returns <code>null</code>.
     * @see #start(InetAddress originatingHost) init( InetAddress originatingHost )
     */
    InetAddress getHostAddress(Serializable sessionId);

    /**
     * Explicitly stops the session identified by <tt>sessionId</tt>, thereby releasing all
     * associated resources.
     *
     * @param sessionId the system identfier of the system to destroy.
     * @throws InvalidSessionException if the session has stopped or expired prior to calling
     *                                 this method.
     * @see org.jsecurity.session.Session#stop
     */
    void stop(Serializable sessionId) throws InvalidSessionException;

    /**
     * Returns the keys of all the attributes stored under the session identified by <tt>sessionId</tt>.
     * If there are no attributes, this returns an empty collection.
     *
     * @param sessionId the system identifier of the system to access.
     * @return the keys of all attributes stored under the specified session, or an empty collection if
     *         there are no session attributes.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#getAttributeKeys()
     * @since 0.2
     */
    Collection<Object> getAttributeKeys(Serializable sessionId);

    /**
     * Returns the object bound to the specified session identified by the specified key.  If there
     * is noobject bound under the key for the given session, <tt>null</tt> is returned.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key       the unique name of the object bound to the specified session
     * @return the object bound under the specified <tt>key</tt> name or <tt>null</tt> if there is
     *         no object bound under that name.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#getAttribute(Object key)
     */
    Object getAttribute(Serializable sessionId, Object key) throws InvalidSessionException;

    /**
     * Binds the specified <tt>value</tt> to the specified session uniquely identified by the
     * specifed <tt>key</tt> name.  If there is already an object bound under the <tt>key</tt>
     * name, that existing object will be replaced by the new <tt>value</tt>.
     *
     * <p>If the <tt>value</tt> parameter is null, it has the same effect as if the
     * {@link #removeAttribute(Serializable sessionId, Object key)} method was called.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key       the name under which the <tt>value</tt> object will be bound in this session
     * @param value     the object to bind in this session.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#setAttribute(Object key, Object value)
     */
    void setAttribute(Serializable sessionId, Object key, Object value) throws InvalidSessionException;

    /**
     * Removes (unbinds) the object bound to this session under the specified <tt>key</tt> name.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key       the name uniquely identifying the object to remove
     * @return the object removed or <tt>null</tt> if there was no object bound under the specified
     *         <tt>key</tt> name.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#removeAttribute(Object key)
     */
    Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException;
}
