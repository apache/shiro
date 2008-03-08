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
package org.jsecurity.session.event.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.event.SessionEvent;
import org.jsecurity.session.event.SessionEventListener;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Simple implementation that synchronously calls any
 * {@link SessionEventListenerRegistrar registered} {@link org.jsecurity.session.event.SessionEventListener listener}s
 * when a <tt>SessionEvent</tt> occurs.
 *
 * @see #setSessionEventListeners
 *
 * @since 0.9
 * @author Les Hazlewood
 */
public class DefaultSessionEventSender implements SessionEventSender, SessionEventListenerRegistrar {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected Collection<SessionEventListener> listeners = null;

    public DefaultSessionEventSender(){}

    public DefaultSessionEventSender( Collection<SessionEventListener> listeners ) {
        this.listeners = listeners;
    }

    public void setSessionEventListeners( Collection<SessionEventListener> listeners ) {
        this.listeners = listeners;
    }

    public Collection<SessionEventListener> getSessionEventListeners() {
        return this.listeners;
    }

    public boolean isSendingEvents() {
        return this.listeners != null && !this.listeners.isEmpty();
    }

    protected Collection<SessionEventListener> getListenersLazy() {
        Collection<SessionEventListener> listeners = getSessionEventListeners();
        if ( listeners == null ) {
            listeners = new ArrayList<SessionEventListener>();
            setSessionEventListeners( listeners );
        }
        return listeners;
    }

    public void add( SessionEventListener listener ) {
        if ( listener == null ) {
            String msg = "Attempting to add a null session event listener";
            throw new IllegalArgumentException( msg );
        }
        Collection<SessionEventListener> listeners = getListenersLazy();
        if ( !listeners.contains( listener ) ) {
            listeners.add( listener );
        }
    }

    public boolean remove( SessionEventListener listener ) {
        boolean removed = false;
        if ( listener != null ) {
            Collection<SessionEventListener> listeners = getSessionEventListeners();
            if ( listeners != null ) {
                removed = listeners.remove( listener );
            }
        }
        return removed;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link SessionEventListener}s.
     */
    public void send( SessionEvent event ) {
        Collection<SessionEventListener> listeners = getSessionEventListeners();
        if ( listeners != null && !listeners.isEmpty() ) {
            for( SessionEventListener sel : listeners ) {
                sel.onEvent( event );
            }
        }
    }
}
