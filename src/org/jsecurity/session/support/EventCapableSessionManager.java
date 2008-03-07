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
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionManager;
import org.jsecurity.session.event.*;

import java.util.Collection;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
public abstract class EventCapableSessionManager implements SessionManager, SessionEventListenerRegistrar {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected SimpleSessionEventSender sessionEventSender = new SimpleSessionEventSender();

    public EventCapableSessionManager(){}

    public void add( SessionEventListener listener ) {
        this.sessionEventSender.add( listener );
    }

    public boolean remove( SessionEventListener listener ) {
        return this.sessionEventSender.remove( listener );
    }

    public void setSessionEventListeners(Collection<SessionEventListener> listeners) {
        this.sessionEventSender = new SimpleSessionEventSender( listeners );
    }

    public boolean isSendingEvents() {
        return this.sessionEventSender.hasListeners();
    }

    protected SessionEvent createStartEvent( Session session ) {
        return new StartedSessionEvent( this, session.getSessionId() );
    }

    protected SessionEvent createStopEvent( Session session ) {
        return new StoppedSessionEvent( this, session.getSessionId() );
    }

    protected SessionEvent createExpireEvent( Session session ) {
        return new ExpiredSessionEvent( this, session.getSessionId() );
    }

    protected void send( SessionEvent event ) {
        this.sessionEventSender.send(event);
    }

    protected void sendStartEvent(Session session) {
        if ( isSendingEvents() ) {
            SessionEvent startEvent = createStartEvent( session );
            send( startEvent );
        }
    }

    protected void sendStopEvent(Session session) {
        if ( isSendingEvents() ) {
            SessionEvent stopEvent = createStopEvent( session );
            send( stopEvent );
        }    
    }

    protected void sendExpireEvent(Session session) {
        if ( isSendingEvents() ) {
            SessionEvent expiredEvent = createExpireEvent(session);
            send( expiredEvent );
        }
    }

}
