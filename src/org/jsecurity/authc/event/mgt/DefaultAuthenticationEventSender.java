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
package org.jsecurity.authc.event.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.AuthenticationEventListener;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Simple implementation that 'sends' an event by synchronously calling any registered
 * {@link org.jsecurity.authc.event.AuthenticationEventListener}s.
 *
 * @see org.jsecurity.authc.event.AuthenticationEventListener#onEvent
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class DefaultAuthenticationEventSender implements AuthenticationEventSender {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected Collection<AuthenticationEventListener> listeners = null;

    public DefaultAuthenticationEventSender(){}

    public DefaultAuthenticationEventSender( Collection<AuthenticationEventListener> listeners ) {
        setAuthenticationEventListeners( listeners );
    }

    public boolean isSendingEvents() {
        return this.listeners != null && !this.listeners.isEmpty();
    }

    /**
     * Sets the <tt>AuthenticationEventListener</tt> collection that will be called when an event is triggered.
     * @param listeners the AuthenticationEventListener collection that will be called when an event is triggered.
     */
    public void setAuthenticationEventListeners( Collection<AuthenticationEventListener> listeners ) {
        this.listeners = listeners;
    }

    public Collection<AuthenticationEventListener> getAuthenticationEventListeners() {
        return listeners;
    }

    protected Collection<AuthenticationEventListener> getListenersLazy() {
        Collection<AuthenticationEventListener> listeners = getAuthenticationEventListeners();
        if ( listeners == null ) {
            listeners = new ArrayList<AuthenticationEventListener>();
            setAuthenticationEventListeners( listeners );
        }
        return listeners;
    }

    public void add(AuthenticationEventListener listener) {
        getListenersLazy().add( listener );
    }

    public boolean remove(AuthenticationEventListener listener) {
        boolean removed = false;
        if ( listener != null ) {
            Collection<AuthenticationEventListener> listeners = getAuthenticationEventListeners();
            if ( listeners != null ) {
                removed = listeners.remove( listener );
            }
        }
        return removed;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link AuthenticationEventListener}s by
     * synchronously calling <tt>listener.onEvent(Event)</tt> for each listener configured in this sender's
     * internal listener list.
     */
    public void send( AuthenticationEvent event ) {
        if ( isSendingEvents() ) {
            for ( AuthenticationEventListener ael : listeners ) {
                ael.onEvent( event );
            }
        } else {
            if ( log.isWarnEnabled() ) {
                String msg = "internal listeners collection is null.  No " +
                    "AuthenticationEventListeners will be notified of event [" +
                    event + "]";
                log.warn( msg );
            }
        }
    }

    /**
     * Adds the given <tt>AuthenticationEventListener</tt> to the internal collection of listeners that will be
     * synchronously called when an event is triggered.
     * @param listener the listener to receive AuthenticationEvents
     */
    public void addListener( AuthenticationEventListener listener ) {
        if ( listener == null ) {
            String msg = "Attempting to add a null authentication event listener";
            throw new IllegalArgumentException( msg );
        }
        if ( !listeners.contains( listener ) ) {
            listeners.add( listener );
        }
    }
}
