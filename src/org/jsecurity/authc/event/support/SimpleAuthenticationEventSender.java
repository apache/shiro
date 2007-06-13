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
package org.jsecurity.authc.event.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.AuthenticationEventListener;
import org.jsecurity.authc.event.AuthenticationEventSender;

import java.util.ArrayList;
import java.util.List;

/**
 * Simple implementation that synchronously calls any registered 
 * {@link org.jsecurity.authc.event.AuthenticationEventListener}s.
 *
 * @see AuthenticationEventListener#onEvent
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class SimpleAuthenticationEventSender implements AuthenticationEventSender {

    protected transient final Log log = LogFactory.getLog( getClass() );

    protected List<AuthenticationEventListener> listeners =
        new ArrayList<AuthenticationEventListener>();

    public void setListeners( List<AuthenticationEventListener> listeners ) {
        if ( listeners == null ) {
            String msg = "listeners argument cannot be null";
            throw new IllegalArgumentException( msg );
        }
        this.listeners = listeners;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link AuthenticationEventListener}s.
     */
    public void send( AuthenticationEvent event ) {
        if ( listeners != null && !listeners.isEmpty() ) {
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

    public void addListener( AuthenticationEventListener listener ) {
        if ( listener == null ) {
            String msg = "Attempting to add a null authentication event listener";
            throw new IllegalArgumentException( msg );
        }
        if ( !listeners.contains( listener ) ) {
            listeners.add( listener );
        }
    }

    public void removeListener( AuthenticationEventListener listener ) {
        if ( listener != null ) {
            listeners.remove( listener );
        }
    }

}
