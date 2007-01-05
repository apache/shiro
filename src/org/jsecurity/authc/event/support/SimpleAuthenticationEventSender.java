/*
 * Copyright (C) 2005 Les Hazlewood
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
import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.LockedAccountException;
import org.jsecurity.authc.event.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Simple implementation of the {@link AuthenticationEventSender} interface that synchronously calls
 * any registered {@link org.jsecurity.authc.event.AuthenticationEventListener}s.
 *
 * @see #setListeners
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
     *
     * @see AuthenticationEventSender#send( org.jsecurity.authc.event.AuthenticationEvent event )
     */
    public void send( AuthenticationEvent event ) {
        if ( listeners != null ) {
            synchronized ( listeners ) {
                for ( AuthenticationEventListener ael : listeners ) {
                    if ( event instanceof SuccessfulAuthenticationEvent) {
                        ael.accountAuthenticated( event );
                    } else if ( event instanceof UnlockedAccountEvent) {
                        ael.accountUnlocked( event );
                    } else if ( event instanceof LogoutEvent) {
                        ael.accountLoggedOut( event );
                    } else if ( event instanceof FailedAuthenticationEvent) {
                        FailedAuthenticationEvent failedEvent = (FailedAuthenticationEvent)event;
                        AuthenticationException cause = failedEvent.getCause();

                        if ( cause != null && ( cause instanceof LockedAccountException ) ) {
                            ael.accountLocked( event );
                        } else {
                            ael.authenticationFailed( event );
                        }
                    } else {
                        String msg = "Received argument of type [" + event.getClass() + "].  This " +
                                     "implementation can only send event instances of types " +
                                     SuccessfulAuthenticationEvent.class.getName() + ", " +
                                     FailedAuthenticationEvent.class.getName() + ", " +
                                     UnlockedAccountEvent.class.getName() + ", or " +
                                     LogoutEvent.class.getName();
                        throw new IllegalArgumentException( msg );
                    }
                }
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
