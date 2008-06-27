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
package org.jsecurity.session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * A <tt>Session</tt> is a data/state context associated with a single Subject (user, 3rd party process,
 * etc) that interacts with a software system over a period of time.
 *
 * <p>A <tt>Session</tt> is intended to be managed by the business tier and accessible via other
 * tiers without being tied to any given client technology.  This is a <em>great</em> benefit to Java
 * systems, since until now, the only viable session mechanisms were the
 * {@link javax.servlet.http.HttpSession HttpSession} or Stateful Session EJB's, which many times
 * unnecessarily coupled applications to web or ejb technologies.
 *
 * <p>See the {@link SessionFactory#getSession(java.io.Serializable) SessionFactory.getSession(Serializable)}
 * JavaDoc for more on the benefits of a POJO-based <tt>Session</tt> framework.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public interface Session {

    /**
     * Returns the unique identifier assigned by the system upon session creation.
     *
     * <p>All return values from this method are expected to have proper <code>toString()</code>,
     * <code>equals()</code>, and <code>hashCode()</code> implementations. Good candiadates for such
     * an identifier are {@link java.util.UUID UUID}s, {@link java.lang.Integer Integer}s, and
     * {@link java.lang.String String}s.
     *
     * @return The unique identifier assigned to the session upon creation.
     */
    Serializable getId();

    /**
     * Returns the time the session was started; that is, the time the system created the instance.
     *
     * @return The time the system created the session.
     */
    Date getStartTimestamp();

    /**
     * Returns the time the session was stopped, or <tt>null</tt> if the session is still active.
     *
     * <p>A session may become stopped under a number of conditions:
     * <ul>
     * <li>If the user logs out of the system, their current session is terminated (released).</li>
     * <li>If the session expires</li>
     * <li>The application explicitly calls {@link #stop() destroy()}</li>
     * <li>If there is an internal system error and the session state can no longer accurately
     * reflect the user's behavior, such in the case of a system crash</li>
     * </ul>
     * </p>
     *
     * <p>Once stopped, a session may no longer be used.  It is locked from all further activity.
     *
     * @return The time the session was stopped, or <tt>null</tt> if the session is still
     *         active.
     */
    Date getStopTimestamp();

    /**
     * Returns the last time the user associated with the session interacted with the system.
     *
     * @return The time the user last interacted with the system.
     * @see #touch()
     */
    Date getLastAccessTime();

    /**
     * Returns true if this session has expired, false otherwise.  If the session has
     * expired, no further user interaction with the system may be done under this session.
     *
     * @return true if this session has expired, false otherwise.
     */
    boolean isExpired();

    /**
     * Returns the time in milliseconds that the session session may remain idle before expiring.
     *
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @return the time in milliseconds the session may remain idle before expiring.
     * @throws org.jsecurity.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @since 0.2
     */
    long getTimeout() throws InvalidSessionException;

    /**
     * Sets the time in milliseconds that the session may remain idle before expiring.
     *
     * <ul>
     * <li>A negative return value means the session will never expire.</li>
     * <li>A non-negative return value (0 or greater) means the session expiration will occur if idle for that
     * length of time.</li>
     * </ul>
     *
     * @param maxIdleTimeInMillis the time in milliseconds that the session may remain idle before expiring.
     * @throws org.jsecurity.session.InvalidSessionException
     *          if the session has been stopped or expired prior to calling this method.
     * @since 0.2
     */
    void setTimeout(long maxIdleTimeInMillis) throws InvalidSessionException;


    /**
     * Returns the <tt>InetAddress</tt> of the host that originated this session, or <tt>null</tt>
     * if the host address is unknown.
     *
     * @return the <tt>InetAddress</tt> of the host that originated this session, or <tt>null</tt>
     *         if the host address is unknown.
     * @see SessionFactory#start(java.net.InetAddress)
     */
    InetAddress getHostAddress();

    /**
     * Explicitly updates the {@link #getLastAccessTime() lastAccessTime} of this session.  This
     * method can be used to ensure a session does not time out.
     *
     * <p>Most programmers won't use this method explicitly and will instead rely calling the other Session methods
     * to update the time transparently, or on a framework during a remote procedure call or upon a web request.
     *
     * <p>This method is particularly useful however when supporting rich-client applications such as
     * Java Web Start appp, Java or Flash applets, etc.  Although rare, it is possible in a rich-client
     * environment that a user continuously interacts with the client-side application without a
     * server-side method call ever being invoked.  If this happens over a long enough period of
     * time, the user's server-side session could time-out.  Again, such cases are rare since most
     * rich-clients frequently require server-side method invocations.
     *
     * <p>In this example though, the user's session might still be considered valid because
     * the user is actively &quot;using&quot; the application, just not communicating with the
     * server. But because no server-side method calls are invoked, there is no way for the server
     * to know if the user is sitting idle or not, so it must assume so to maintain session
     * integrity.  The touch method could be invoked by the rich-client application code during those
     * times to ensure that the next time a server-side method is invoked, the invocation will not
     * throw an {@link ExpiredSessionException ExpiredSessionException}.  In short terms, it could be used periodically
     * to ensure a session does not time out.
     *
     * <p>How often this rich-client &quot;maintenance&quot; might occur is entirely dependent upon
     * the application and would be based on variables such as session timeout configuration,
     * usage characteristics of the client application, network utilization and application server
     * performance.
     *
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     *                                 this method.
     */
    void touch() throws InvalidSessionException;

    /**
     * Explicitly stops this session and releases all associated resources.
     *
     * <p>If this session has already been authenticated (i.e. the user associated with this
     * session has logged-in and has a {@link org.jsecurity.subject.Subject Subject} ),
     * this method should only be called during the logout process, when it is
     * considered a graceful operation.
     *
     * <p><b>N.B.</b> Under most applications' circumstances, it is usually far better to stop the session implicitly
     * by logging-out the 'owning' <tt>Subject</tt> instead.  This is done by calling the
     * {@link org.jsecurity.subject.Subject#logout Subject#logout} method, since
     * <tt>logout</tt> is expected to stop the corresponding session automatically, and also allows the framework
     * to do any other additional cleanup.
     *
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     *                                 this method.
     * @see #getStopTimestamp
     */
    void stop() throws InvalidSessionException;

    /**
     * Returns the keys of all the attributes stored under this session.  If there are no
     * attributes, this returns an empty collection.
     *
     * @return the keys of all attributes stored under this session, or an empty collection if
     *         there are no session attributes.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling this method.
     * @since 0.2
     */
    Collection<Object> getAttributeKeys() throws InvalidSessionException;

    /**
     * Returns the object bound to this session identified by the specified key.  If there is no
     * object bound under the key, <tt>null</tt> is returned.
     *
     * @param key the unique name of the object bound to this session
     * @return the object bound under the specified <tt>key</tt> name or <tt>null</tt> if there is
     *         no object bound under that name.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     *                                 this method.
     */
    Object getAttribute(Object key) throws InvalidSessionException;

    /**
     * Binds the specified <tt>value</tt> to this session, uniquely identified by the specifed
     * <tt>key</tt> name.  If there is already an object bound under the <tt>key</tt> name, that
     * existing object will be replaced by the new <tt>value</tt>.
     *
     * <p>If the <tt>value</tt> parameter is null, it has the same effect as if
     * <tt>removeAttribute(key)</tt> was called.
     *
     * @param key   the name under which the <tt>value</tt> object will be bound in this session
     * @param value the object to bind in this session.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     *                                 this method.
     */
    void setAttribute(Object key, Object value) throws InvalidSessionException;

    /**
     * Removes (unbinds) the object bound to this session under the specified <tt>key</tt> name.
     *
     * @param key the name uniquely identifying the object to remove
     * @return the object removed or <tt>null</tt> if there was no object bound under the name
     *         <tt>key</tt>.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     *                                 this method.
     */
    Object removeAttribute(Object key) throws InvalidSessionException;
}
