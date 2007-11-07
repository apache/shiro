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
package org.jsecurity.session.event.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.event.SessionEvent;
import org.jsecurity.session.event.SessionEventListener;
import org.jsecurity.session.event.SessionEventListenerRegistry;
import org.jsecurity.session.event.SessionEventSender;

import java.util.ArrayList;
import java.util.List;

/**
 * Simple implementation of the {@link SessionEventSender} interface that synchronously calls any
 * registered {@link org.jsecurity.session.event.SessionEventListener}s.
 *
 * @see #setListeners
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SimpleSessionEventSender implements SessionEventListenerRegistry, SessionEventSender {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected List<SessionEventListener> listeners = new ArrayList<SessionEventListener>();

    public void setListeners( List<SessionEventListener> listeners ) {
        this.listeners = listeners;
    }

    public void add( SessionEventListener listener ) {
        if ( listener == null ) {
            String msg = "Attempting to add a null session event listener";
            throw new IllegalArgumentException( msg );
        }
        if ( !listeners.contains( listener ) ) {
            listeners.add( listener );
        }
    }

    public boolean remove( SessionEventListener listener ) {
        boolean removed = false;
        if ( listener != null ) {
            removed = listeners.remove( listener );
        }
        return removed;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link SessionEventListener}s.
     * 
     * @see SessionEventSender#send( org.jsecurity.session.event.SessionEvent event )
     */
    public void send( SessionEvent event ) {
        if ( listeners != null && !listeners.isEmpty() ) {
            for( SessionEventListener sel : listeners ) {
                sel.onEvent( event );
            }
        }
    }
}
