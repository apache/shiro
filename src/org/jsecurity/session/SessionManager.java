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
package org.jsecurity.session;

import org.jsecurity.authz.HostUnauthorizedException;

import java.io.Serializable;
import java.net.InetAddress;
import java.security.Principal;
import java.util.Date;

/**
 * A SessionManager manages the creation, maintenance, and clean-up of {@link org.jsecurity.session.Session sessions}.
 *
 * @since 0.1
 * @author Les Hazlewood
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
     * (user, 3rd party product, etc) that is attempting to interact with the system.
     * 
     * @return the system identifier of the newly created session.
     *
     * @see org.jsecurity.session.SessionFactory#start(InetAddress)
     */
    Serializable start( InetAddress originatingHost )
        throws HostUnauthorizedException, IllegalArgumentException;

    /**
     * Returns the time the Session identified by the specified <tt>sessionId</tt> was started
     * in the system.
     * @param sessionId the system identifier for the session of interest.
     * @return the system time the specified session was started (i.e. created).
     * @see org.jsecurity.session.Session#getStartTimestamp()
     */
    Date getStartTimestamp( Serializable sessionId );

    /**
     * Returns the time the <tt>Session</tt> identified by the specified <tt>sessionId</tt> was
     * stopped or expired in the system, or <tt>null</tt> if the session is still active. A
     * session could be stopped for a number of reasons.  See the
     * {@link org.jsecurity.session.Session#stop() Session.destroy()} method for more details.
     *
     * @param sessionId
     * @return the system time the session stopped or expired, or <tt>null</tt> if the session
     * is still active.
     * @see org.jsecurity.session.Session#getStopTimestamp()
     */
    Date getStopTimestamp( Serializable sessionId );

    /**
     * Returns the time the <tt>Session</tt> identified by the specified <tt>sessionId</tt> last
     * interacted with the system.  Any interaction with the system generally updates the last
     * access time for a session, with the exception of the methods in the
     * {@link org.jsecurity.session.Session Session} itself (excluding {@link org.jsecurity.session.Session#touch() Session.touch()}).
     * @param sessionId the system identifier for the session of interest
     * @return tye time the session last accessed the system
     * @see org.jsecurity.session.Session#getLastAccessTime()
     * @see org.jsecurity.session.Session#touch()
     */
    Date getLastAccessTime( Serializable sessionId );

    /**
     * Returns <tt>true</tt> if the session with the specified <tt>sessionId</tt> has been
     * stopped, <tt>false</tt> otherwise.
     * @param sessionId the id of the session to check
     * @return <tt>true</tt> if the session has been stopped, <tt>false</tt> otherwise.
     */
    boolean isStopped( Serializable sessionId );

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
    boolean isExpired( Serializable sessionId );

    /**
     * Updates the last accessed time of the session identified by <code>sessionId</code>.  This
     * can be used to explicitly ensure that a session does not time out.
     *
     * @see org.jsecurity.session.Session#touch
     *
     * @param sessionId the id of the session to update.
     * @throws org.jsecurity.session.InvalidSessionException if the session has expired prior to calling this method.
     */
    void touch( Serializable sessionId ) throws InvalidSessionException;

    /**
     * Returns the principal of the authenticated user or entity that initiated the session
     * identified by <code>sessionId</code>, if known.  A session is usually created before an
     * authc takes place, so this method may return <code>null</code> if the principal
     * is unknown or the session hasn't yet been authenticated.
     *
     * <p>For example, in a web-based system, just visiting the first web page usually initiates a
     * session.  But if that web page happens to be the log-in page, the session that was created
     * hasn't yet been authenticated.  In this case, there is no principal (i.e. username
     * in this case) yet associated with the session.
     *
     * <p>However, if the user submits the log-in form and is successful, this method could
     * then be called to get the principal (username) of that person.
     *
     * <p>The principal itself can be any valid Java security principal.  In the above example, it
     * was a username.  In other systems (especially RDBMS-based ones) it is often an
     * entity/user id such as a UUID or Integer or even a Public Key.
     *
     * @return the identifying principal of the user or entity that authenticated this session,
     * or <code>null</code> if this session hasn't yet been authenticated.
     */
    Principal getPrincipal( Serializable sessionId );


    /**
     * Returns the IP address of the host where the session was started, if known.  If
     * no IP was specified when starting the session, this method returns <code>null</code>
     * @param sessionId the id of the session to query.
     *
     * @return the ip address of the host where the session originated, if known.  If unknown,
     * this method returns <code>null</code>.
     *
     * @see #start( InetAddress originatingHost ) init( InetAddress originatingHost )
     */
    InetAddress getHostAddress( Serializable sessionId );

    /**
     * Explicitly stops the session identified by <tt>sessionId</tt>, thereby releasing all
     * associated resources.
     * @param sessionId the system identfier of the system to destroy.
     * @throws InvalidSessionException if the session has stopped or expired prior to calling
     * this method.
     * @see org.jsecurity.session.Session#stop
     */
    void stop( Serializable sessionId ) throws InvalidSessionException;

    /**
     * Returns the object bound to the specified session identified by the specified key.  If there
     * is noobject bound under the key for the given session, <tt>null</tt> is returned.
     * @param sessionId the system identifier of the session of interest
     * @param key the unique name of the object bound to the specified session
     * @return the object bound under the specified <tt>key</tt> name or <tt>null</tt> if there is
     * no object bound under that name.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#getAttribute(Object key)
     */
    Object getAttribute( Serializable sessionId, Object key ) throws InvalidSessionException;

    /**
     * Binds the specified <tt>value</tt> to the specified session uniquely identified by the
     * specifed <tt>key</tt> name.  If there is already an object bound under the <tt>key</tt>
     * name, that existing object will be replaced by the new <tt>value</tt>.
     *
     * <p>If the <tt>value</tt> parameter is null, it has the same effect as if the
     * {@link #removeAttribute(Serializable sessionId, Object key)} method was called.
     *
     * @param sessionId the system identifier of the session of interest
     * @param key the name under which the <tt>value</tt> object will be bound in this session
     * @param value the object to bind in this session.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#setAttribute(Object key, Object value)
     */
    void setAttribute( Serializable sessionId, Object key, Object value ) throws InvalidSessionException;

    /**
     * Removes (unbinds) the object bound to this session under the specified <tt>key</tt> name.
     * @param sessionId the system identifier of the session of interest
     * @param key the name uniquely identifying the object to remove
     * @return the object removed or <tt>null</tt> if there was no object bound under the specified 
     * <tt>key</tt> name.
     * @throws InvalidSessionException if the specified session has stopped or expired prior to calling this method.
     * @see org.jsecurity.session.Session#removeAttribute(Object key)
     */
    Object removeAttribute( Serializable sessionId, Object key ) throws InvalidSessionException;


}
