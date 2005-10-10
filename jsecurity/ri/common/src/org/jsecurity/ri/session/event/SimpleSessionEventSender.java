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
package org.jsecurity.ri.session.event;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.SessionEvent;

import java.util.List;
import java.util.ArrayList;

/**
 * Simple implementation of the {@link SessionEventSender} interface that synchronously calls any
 * registered {@link org.jsecurity.session.event.SessionEventListener}s.
 *
 * @see #setListeners
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SimpleSessionEventSender implements SessionEventSender {

    protected transient final Log log = LogFactory.getLog( getClass() );


    protected List<SessionEventListener> listeners = new ArrayList<SessionEventListener>();

    public void setListeners( List<SessionEventListener> listeners ) {
        this.listeners = listeners;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link SessionEventListener}s.
     * 
     * @see SessionEventSender#send( org.jsecurity.session.event.SessionEvent event )
     */
    public void send( SessionEvent event ) {
        synchronized( listeners ) {
            for( SessionEventListener sel : listeners ) {
                if ( event instanceof StartedSessionEvent ) {
                    sel.sessionStarted( event );
                } else if ( event instanceof ExpiredSessionEvent ) {
                    sel.sessionExpired( event );
                } else if ( event instanceof StoppedSessionEvent ) {
                    sel.sessionStopped( event );
                } else {
                    String msg = "Received argument of type [" + event.getClass() + "].  This " +
                                 "implementation can only send event instances of types " +
                        StartedSessionEvent.class.getName() + ", " +
                        ExpiredSessionEvent.class.getName() + ", or " +
                        StoppedSessionEvent.class.getName();
                    throw new IllegalArgumentException( msg );
                }
            }
        }
    }

    public void addSessionEventListener( SessionEventListener listener ) {
        if ( listener == null ) {
            String msg = "Attempting to add a null session event listener";
            throw new IllegalArgumentException( msg );
        }
        if ( !listeners.contains( listener ) ) {
            listeners.add( listener );
        }
    }

    public void removeSessionEventListener( SessionEventListener listener ) {
        if ( listener != null ) {
            listeners.remove( listener );
        }
    }

}
