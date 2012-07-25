/*
 * Copyright 2008 Les Hazlewood
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
package org.apache.shiro.session.mgt;

import org.apache.shiro.session.InvalidSessionException;

import java.util.Collection;
import java.util.Date;

/**
 * A {@code Native} session manager is one that manages sessions natively - that is, it is directly responsible
 * for the creation, persistence and removal of {@link org.apache.shiro.session.Session Session} instances and their
 * lifecycles.
 *
 * @since 1.0
 */
public interface NativeSessionManager extends SessionManager {

    /**
     * Returns the time the associated {@code Session} started (was created).
     *
     * @param key the session key to use to look up the target session.
     * @return the time the specified {@code Session} started (was created).
     * @see org.apache.shiro.session.Session#getStartTimestamp()
     */
    Date getStartTimestamp(SessionKey key);

    /**
     * Returns the time the associated {@code Session} last interacted with the system.
     *
     * @param key the session key to use to look up the target session.
     * @return time the session last accessed the system
     * @see org.apache.shiro.session.Session#getLastAccessTime()
     * @see org.apache.shiro.session.Session#touch()
     */
    Date getLastAccessTime(SessionKey key);

    /**
     * Returns {@code true} if the associated session is valid (it exists and is not stopped nor expired),
     * {@code false} otherwise.
     *
     * @param key the session key to use to look up the target session.
     * @return {@code true} if the session is valid (exists and is not stopped or expired), {@code false} otherwise.
     */
    boolean isValid(SessionKey key);

    /**
     * Returns quietly if the associated session is valid (it exists and is not stopped or expired) or throws
     * an {@link org.apache.shiro.session.InvalidSessionException} indicating that the session id is invalid.  This
     * might be preferred to be used instead of {@link #isValid} since any exception thrown will definitively explain
     * the reason for invalidation.
     *
     * @param key the session key to use to look up the target session.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session id is invalid (it does not exist or it is stopped or expired).
     */
    void checkValid(SessionKey key) throws InvalidSessionException;

    /**
     * Returns the time in milliseconds that the associated session may remain idle before expiring.
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param key the session key to use to look up the target session.
     * @return the time in milliseconds that the associated session may remain idle before expiring.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     */
    long getTimeout(SessionKey key) throws InvalidSessionException;

    /**
     * Sets the time in milliseconds that the associated session may remain idle before expiring.
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param key                 the session key to use to look up the target session.
     * @param maxIdleTimeInMillis the time in milliseconds that the associated session may remain idle before expiring.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     */
    void setTimeout(SessionKey key, long maxIdleTimeInMillis) throws InvalidSessionException;

    /**
     * Updates the last accessed time of the session identified by <code>sessionId</code>.  This
     * can be used to explicitly ensure that a session does not time out.
     *
     * @param key the session key to use to look up the target session.
     * @throws org.apache.shiro.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#touch
     */
    void touch(SessionKey key) throws InvalidSessionException;

    /**
     * Returns the host name or IP string of the host where the session was started, if known.  If
     * no host name or IP was specified when starting the session, this method returns {@code null}
     *
     * @param key the session key to use to look up the target session.
     * @return the host name or ip address of the host where the session originated, if known.  If unknown,
     *         this method returns {@code null}.
     */
    String getHost(SessionKey key);

    /**
     * Explicitly stops the associated session, thereby releasing all of its resources.
     *
     * @param key the session key to use to look up the target session.
     * @throws InvalidSessionException if the session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#stop
     */
    void stop(SessionKey key) throws InvalidSessionException;

    /**
     * Returns all attribute keys maintained by the target session or an empty collection if there are no attributes.
     *
     * @param sessionKey the session key to use to look up the target session.
     * @return all attribute keys maintained by the target session or an empty collection if there are no attributes.
     * @throws InvalidSessionException if the associated session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#getAttributeKeys()
     */
    Collection<Object> getAttributeKeys(SessionKey sessionKey);

    /**
     * Returns the object bound to the associated session identified by the specified attribute key.  If there
     * is no object bound under the attribute key for the given session, {@code null} is returned.
     *
     * @param sessionKey   session key to use to look up the target session.
     * @param attributeKey the unique name of the object bound to the associated session
     * @return the object bound under the {@code attributeKey} or {@code null} if there is no object bound.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#getAttribute(Object key)
     */
    Object getAttribute(SessionKey sessionKey, Object attributeKey) throws InvalidSessionException;

    /**
     * Binds the specified {@code value} to the associated session uniquely identified by the {@code attributeKey}.
     * If there is already a session attribute bound under the {@code attributeKey}, that existing object will be
     * replaced by the new {@code value}.
     * <p/>
     * If the {@code value} parameter is null, it has the same effect as if the
     * {@link #removeAttribute(SessionKey sessionKey, Object attributeKey)} method was called.
     *
     * @param sessionKey   the session key to use to look up the target session.
     * @param attributeKey the key under which the {@code value} object will be bound in this session
     * @param value        the object to bind in this session.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#setAttribute(Object key, Object value)
     */
    void setAttribute(SessionKey sessionKey, Object attributeKey, Object value) throws InvalidSessionException;

    /**
     * Removes (unbinds) the object bound to associated {@code Session} under the given {@code attributeKey}.
     *
     * @param sessionKey   session key to use to look up the target session.
     * @param attributeKey the key uniquely identifying the object to remove
     * @return the object removed or {@code null} if there was no object bound under the specified {@code attributeKey}.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.apache.shiro.session.Session#removeAttribute(Object key)
     */
    Object removeAttribute(SessionKey sessionKey, Object attributeKey) throws InvalidSessionException;

}
