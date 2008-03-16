/*
 * Copyright 2005-2008 Les Hazlewood, Jeremy Haile
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
package org.jsecurity.session.mgt;

import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * A DelegatingSession is a client-tier representation of a server side
 * {@link org.jsecurity.session.Session Session}.
 * This implementation is basically a proxy to a server-side {@link SessionManager SessionManager},
 * which will return the proper results for each method call.
 *
 * <p>A <tt>DelegatingSession</tt> will cache data when appropriate to avoid a remote method invocation,
 * only communicating with the server when necessary (for example, when determining if
 * {@link #isExpired() isExpired()}, which can only be accurately known by the server).
 *
 * <p>Of course, if used in-process with a SessionManager business POJO, as might be the case in a
 * web-based application where the web classes and server-side business pojos exist in the same
 * JVM, a remote method call will not be incurred.
 *
 * @since 0.1
 * @author Les Hazlewood
 * @author Jeremy Haile
 */
public class DelegatingSession implements Session {

    private Serializable id = null;

    //cached fields to avoid a server-side method call if out-of-process:
    private Date startTimestamp = null;
    private Date stopTimestamp = null;
    private InetAddress hostAddress = null;

    /**
     * Handle to a server-side SessionManager.  See {@link #setSessionManager} for details.
     */
    private SessionManager sessionManager = null;


    public DelegatingSession(){}

    public DelegatingSession( SessionManager sessionManager, Serializable id) {
        this.sessionManager = sessionManager;
        this.id = id;
    }

    /**
     * Returns the {@link SessionManager SessionManager} used by this handle to invoke
     * all session-related methods.
     * @return the {@link SessionManager SessionManager} used by this handle to invoke
     * all session-related methods.
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
     *
     * <p>You'll notice the {@link Session Session} interface and the {@link SessionManager}
     * interface are nearly identical.  This is to ensure the SessionManager can support
     * most method calls in the Session interface, via this handle/proxy technique.  The session
     * manager is implementated as a stateless business POJO, with the handle passing the
     * session id as necessary.
     *
     * @param sessionManager the <tt>SessionManager</tt> this handle will use when delegating
     * method calls.
     */
    public void setSessionManager( SessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    /**
     * Sets the sessionId used by this handle for all future {@link SessionManager SessionManager}
     * method invocations.
     * @param id the <tt>sessionId</tt> to use for all <tt>SessionManager</tt> invocations.
     * @see #setSessionManager( SessionManager sessionManager )
     */
    public void setId( Serializable id) {
        this.id = id;
    }

    /**
     * @see Session#getId()
     */
    public Serializable getId() {
        return id;
    }

    /**
     * @see Session#getStartTimestamp()
     */
    public Date getStartTimestamp() {
        if ( startTimestamp == null ) {
            startTimestamp = sessionManager.getStartTimestamp(id);
        }
        return startTimestamp;
    }

    /**
     * @see Session#getStopTimestamp()
     */
    public Date getStopTimestamp() {
        if ( stopTimestamp == null ) {
            stopTimestamp = sessionManager.getStopTimestamp(id);
        }
        return stopTimestamp;
    }

    /**
     * @see org.jsecurity.session.Session#getLastAccessTime()
     */
    public Date getLastAccessTime() {
        //can't cache - only business pojo knows the accurate time:
        return sessionManager.getLastAccessTime(id);
    }

    /**
     * @see org.jsecurity.session.Session#isExpired()
     */
    public boolean isExpired() {
        //can't cache - only business pojo knows the accurate time for expiration:
        return sessionManager.isExpired(id);
    }

    public long getTimeout() throws InvalidSessionException {
        return sessionManager.getTimeout(id);
    }

    public void setTimeout( long maxIdleTimeInMillis ) throws InvalidSessionException {
        sessionManager.setTimeout(id, maxIdleTimeInMillis );
    }

    /**
     * @see org.jsecurity.session.Session#getHostAddress()
     */
    public InetAddress getHostAddress() {
        if ( hostAddress == null ) {
            hostAddress = sessionManager.getHostAddress(id);
        }
        return hostAddress;
    }

    /**
     * @see org.jsecurity.session.Session#touch()
     */
    public void touch() throws InvalidSessionException {
        sessionManager.touch(id);
    }

    /**
     * @see org.jsecurity.session.Session#stop()
     */
    public void stop() throws InvalidSessionException {
        sessionManager.stop(id);
    }

    /**
     * @see org.jsecurity.session.Session#getAttributeKeys
     */
    public Collection<Object> getAttributeKeys() throws InvalidSessionException {
        return sessionManager.getAttributeKeys(id);
    }

    /**
     * @see Session#getAttribute(Object key)
     */
    public Object getAttribute( Object key ) throws InvalidSessionException {
        return sessionManager.getAttribute(id, key );
    }

    /**
     * @see Session#setAttribute(Object key, Object value)
     */
    public void setAttribute( Object key, Object value ) throws InvalidSessionException {
        if ( value == null ) {
            removeAttribute( key );
        } else {
            sessionManager.setAttribute(id, key, value );
        }
    }

    /**
     * @see Session#removeAttribute(Object key)
     */
    public Object removeAttribute( Object key ) throws InvalidSessionException {
        return sessionManager.removeAttribute(id, key );
    }
}
