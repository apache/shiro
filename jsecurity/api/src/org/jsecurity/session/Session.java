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


import java.security.Principal;
import java.util.Calendar;
import java.io.Serializable;
import java.net.InetAddress;

/**
 * @author Les Hazlewood
 */
public interface Session {

    /**
     * Returns the unique identifier assigned by the system upon session creation.
     *
     * <p>All return values from this method are expected to have a proper toString() function
     * such that the system identifier can be easily read by a human.  Good candiadates for such
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
     *
     * @return The unique identifier assigned to the session upon creation.
     */
    Serializable getSessionId();

    /**
     * Returns the time this session was started, i.e. the time the system created the instance.
     * @return The time the system created this session.
     */
    Calendar getStartTimestamp();

    /**
     * Returns the time this session was stopped.
     *
     * <p>A session may become stopped under a number of conditions:
     * <ul>
     *   <li>If the user logs out of the system, their current session is terminated (released).</li>
     *   <li>If the session expires</li>
     *   <li>The application explicitly calls {@link #stop() stop()}</li>
     *   <li>If there is an internal system error and the session state can no longer accurately
     *       reflect the user's behavior, such in the case of a system crash</li>
     * </ul>
     *
     * <p>Once stopped, a session may no longer be used.  It is locked from all further activity.
     *
     * @return The time this session was stopped, or <tt>null</tt> if this session is still
     * active.
     */
    Calendar getStopTimestamp();

    /**
     * Returns the last time the user interacted with the system.  With the exception of the
     * {@link #touch()} method, merely calling the other methods on this interface will not
     * update the last access time.
     *
     * @return The time the user last interacted with the system.
     */
    Calendar getLastAccessTime();

    /**
     * Returns whether or not this session has expired.  If so, no further user interaction may be
     * done with the system under this session.
     *
     * @return true if this session has expired, false otherwise.
     */
    boolean isExpired();


    /**
     * Returns the principal of the authenticated user or entity that initiated this session, if
     * known.  A session is usually created before an authentication takes place, so this method
     * may return <code>null</code> if the principal is unknown or the session hasn't yet been
     * authenticated.
     * @return the identifying principal of the user or entity that authenticated this session,
     * or <code>null</code> if this session hasn't yet been authenticated.
     */
    Principal getPrincipal();

    /**
     * Returns the <tt>InetAddress</tt> of the host that originated this session, if known.  Returns
     * <tt>null</tt> if the host is unknown.
     *
     * @return the <tt>InetAddress</tt> of the host that originated this session, or <tt>null</tt>
     * if the host address is unknown.
     */
    InetAddress getHostAddress();

    /**
     * Forces an update of the {@link #getLastAccessTime() last accessed time} of this session.
     *
     * See the {@link SessionManager#touch} method for a good example of when this method might
     * be useful.
     *
     * @see SessionManager#touch
     */
    void touch();

    /**
     * Explicitly stops this session.
     *
     * <p>If this session has already been authenticated (i.e. the user has logged-in),
     * this method should only be called during the logout process, when this method is
     * considered a graceful operation.
     *
     * <p>Calling this method on an authenticated
     * session <em>without</em> first logging the user out is considered an ungraceful operation,
     * as doing so prevents system from updating session data indicating that the user
     * explicitly logged out.
     *
     * <p>If this session has not yet been authenticated, this method may be called at any time.
     */
    void stop();
}
