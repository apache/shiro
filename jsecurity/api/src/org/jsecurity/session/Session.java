/*
 * Copyright (C) 2005 Les A. Hazlewood
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
package org.jsecurity.session;


import java.io.Serializable;
import java.net.InetAddress;
import java.util.Date;

/**
 * A <tt>Session</tt> is a data context associated with a single entity (user, 3rd party process,
 * etc) that communicates with a software system over a period of time.
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
 * @since 1.0
 * @author Les Hazlewood
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
     * <p>This method was not called <code>getId()</code> or <code>getID()</code> as a convenience
     * to the many systems that may already be using such a method name to identify objects
     * internally.  If they exist, these methods most likely return a database primary key
     * (such as a UUID or Integer).
     *
     * <p>In these types of systems, it would probably make sense for an implementation of this
     * interface to return that internal identifier.  For example:<br/><br/>
     *
     * <pre>
     * public Serializable getSessionId() {
     *     return getId(); //system specific identifier
     * }</pre>
     *
     * @return The unique identifier assigned to the session upon creation.
     */
    Serializable getSessionId();

    /**
     * Returns the time the session was started; that is, the time the system created the instance.
     * @return The time the system created the session.
     */
    Date getStartTimestamp();

    /**
     * Returns the time the session was stopped, or <tt>null</tt> if the session is still active.
     *
     * <p>A session may become stopped under a number of conditions:
     * <ul>
     *   <li>If the user logs out of the system, their current session is terminated (released).</li>
     *   <li>If the session expires</li>
     *   <li>The application explicitly calls {@link #stop() stop()}</li>
     *   <li>If there is an internal system error and the session state can no longer accurately
     *       reflect the user's behavior, such in the case of a system crash</li>
     * </ul>
     * </p>
     *
     * <p>Once stopped, a session may no longer be used.  It is locked from all further activity.
     *
     * @return The time the session was stopped, or <tt>null</tt> if the session is still
     * active.
     */
    Date getStopTimestamp();

    /**
     * Returns the last time the account associated with the session interacted with the system.
     * <p>A <tt>Session</tt>'s last access time is updated when calling the following methods:
     * <ul>
     *   <li>{@link #touch() touch()}</li>
     *   <li>{@link #stop() stop()}</li>
     *   <li></li>
     *   <li></li>
     *   <li></li>
     * </ul>.
     * With the exception of the following five methods, {@link #stop()},  method, calling this or other
     * Calling other methods on this interface will <em>not</em> update the last access time.
     * methods on the Session will <em>not</em> update the last access time.
     *
     * @return The time the user last interacted with the system.
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
     * Returns the <tt>InetAddress</tt> of the host that originated this session, or <tt>null</tt>
     * if the host address is unknown.
     *
     * @return the <tt>InetAddress</tt> of the host that originated this session, or <tt>null</tt>
     * if the host address is unknown.
     *
     * @see SessionFactory#start(java.net.InetAddress)
     */
    InetAddress getHostAddress();

    /**
     * Explicitly updates the {@link #getLastAccessTime() lastAccessTime} of this session.  This
     * method can be used to ensure a session does not time out.
     *
     * <p>Most applications won't use
     * this method explicitly and will instead rely on a framework to update the last access time
     * transparently, either upon a web request or a remote method invocation, or via some other
     * mechanism.
     *
     * <p>This method is particularly useful when supporting rich-client applications such as
     * Java Web Start apps or Java applets.  Although rare, it is possible in a rich-client
     * environment that a user continuously interacts with the client-side application without a
     * server-side method call ever being invoked.  If this happens over a long enough period of
     * time, and the server is configured to expire sessions, the user's session could time-out.
     * Again, such cases are rare since most rich-clients frequently require server-side method
     * invocations.
     *
     * <p>In this example though, the user's session might still be considered valid because
     * the user is actively &quot;using&quot; the application, just not communicating with the server.
     * But because no server-side method calls are invoked,
     * there is no way for the server to know if the user is sitting idle or not, so it must assume
     * so to maintain session integrity.  This method could be invoked by the rich-client
     * application code during those times to ensure that the next time a server-side method
     * is invoked,  the invocation will not throw an
     * {@link ExpiredSessionException ExpiredSessionException}.
     *
     * <p>How often this rich-client &quot;maintenance&quot; might occur is entirely dependent upon
     * the application and would be based on variables such as session timeout configuration,
     * usage characteristics of the client application, network utilization and application server
     * performance.
     *
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     * this method.
     */
    void touch() throws InvalidSessionException;

    /**
     * Explicitly stops this session and releases all associated resources.
     *
     * <p>If this session has already been authenticated (i.e. the user associated with this
     * session has logged-in),
     * this method should only be called during the logout process, when it is
     * considered a graceful operation.
     *
     * <p>Calling this method on an authenticated
     * session <em>without</em> first logging the user out is considered an ungraceful operation,
     * as doing so prevents system from updating session data indicating that the user
     * explicitly logged out.
     *
     * <p>If the session has not yet been authenticated, this method may be called at any time.
     *
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     * this method.
     *
     * @see #getStopTimestamp
     */
    void stop() throws InvalidSessionException;

    /**
     * Returns the object bound to this session identified by the specified key.  If there is no
     * object bound under the key, <tt>null</tt> is returned.
     * @param key the unique name of the object bound to this session
     * @return the object bound under the specified <tt>key</tt> name or <tt>null</tt> if there is
     * no object bound under that name.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     * this method.
     */
    Object getAttribute( Object key ) throws InvalidSessionException;

    /**
     * Binds the specified <tt>value</tt> to this session, uniquely identified by the specifed
     * <tt>key</tt> name.  If there is already an object bound under the <tt>key</tt> name, that
     * existing object will be replaced by the new <tt>value</tt>.
     *
     * <p>If the <tt>value</tt> parameter is null, it has the same effect as if
     * <tt>removeAttribute(key)</tt> was called.
     *
     * @param key the name under which the <tt>value</tt> object will be bound in this session
     * @param value the object to bind in this session.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     * this method.
     */
    void setAttribute( Object key, Object value ) throws InvalidSessionException;

    /**
     * Removes (unbinds) the object bound to this session under the specified <tt>key</tt> name.
     * @param key the name uniquely identifying the object to remove
     * @return the object removed or <tt>null</tt> if there was no object bound under the name
     * <tt>key</tt>.
     * @throws InvalidSessionException if this session has stopped or expired prior to calling
     * this method.
     */
    Object removeAttribute( Object key ) throws InvalidSessionException;
}
