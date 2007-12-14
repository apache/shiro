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
package org.jsecurity.session.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.*;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.SessionEventListenerRegistry;
import org.jsecurity.util.Initializable;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * Default JSecurity implementation of a {@link org.jsecurity.session.SessionFactory}.
 * This implementation returns instances where all method invocations delegate to a corresponding
 * {@link org.jsecurity.session.SessionManager SessionManager} method call.  That is, the
 * objects returned act as transparent proxies to the SessionManager responsible for all Sessions
 * in a system.
 *
 * <p>This transparent proxy/delegate technique allows the JSecurity support classes to
 * maintain a stateless architecture (i.e. similar to accessing a EJB Stateless Session Bean),
 * which is extremely efficient.  Any state to be maintained is the responsibility of the
 * SessionManager, not your application, thereby making your code much cleaner and more efficient.
 *
 * <p><tt>Sessions</tt> returned from this factory implementation are extremely lightweight and are
 * designed to be created as needed.  They should not be cached long-term in the
 * business/server tier (e.g. in an <tt>HttpSession</tt> or in some
 * private class {@link java.util.Map Map} attribute).
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class DefaultSessionFactory implements SessionFactory, SessionEventListenerRegistry, Initializable {

    protected final transient Log log = LogFactory.getLog( getClass() );

    protected SessionManager sessionManager = null;
    private boolean sessionManagerImplicitlyCreated = false;

    public DefaultSessionFactory(){}

    public DefaultSessionFactory( SessionManager sessionManager ) {
        setSessionManager( sessionManager );
        init();
    }

    private void assertSessionManagerEventListenerRegistry() {
        if ( !(this.sessionManager instanceof SessionEventListenerRegistry ) ) {
            String msg = "The " + getClass().getName() + " implementation requires its underlying SessionManager " +
                "instance to implement the SessionEventListenerRegistry interface for listener registration " +
                "propagation.";
            throw new IllegalArgumentException( msg );
        }
    }

    public void setSessionManager( SessionManager sessionManager ) {
        assertSessionManagerEventListenerRegistry();
        this.sessionManager = sessionManager;
    }

    public void add( SessionEventListener listener ) {
        ((SessionEventListenerRegistry)this.sessionManager).add( listener );
    }

    public boolean remove( SessionEventListener listener ) {
        return ((SessionEventListenerRegistry)this.sessionManager).remove( listener );
    }

    public void init() {
        if ( this.sessionManager == null ) {
            String msg = "sessionManager property must be set";
            throw new IllegalStateException( msg );
        }
        assertSessionManagerEventListenerRegistry();
    }

    public Session start( InetAddress hostAddress )
        throws HostUnauthorizedException, IllegalArgumentException {
        
        Serializable sessionId = sessionManager.start( hostAddress );
        return new DelegatingSession( sessionManager, sessionId );
    }

    public Session getSession( Serializable sessionId )
        throws InvalidSessionException, AuthorizationException {

        if ( sessionManager.isExpired( sessionId ) ) {
            String msg = "Session with id [" + sessionId + "] has expired and may not " +
                         "be used.";
            throw new ExpiredSessionException( msg );
        } else if ( sessionManager.isStopped( sessionId ) ) {
            String msg = "Session with id [" + sessionId + "] has been stopped and may not " +
                         "be used.";
            throw new StoppedSessionException( msg );
        }

        return new DelegatingSession( sessionManager, sessionId );
    }

}
