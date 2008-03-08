package org.jsecurity.authc.event.mgt;

import org.jsecurity.authc.event.AuthenticationEvent;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface AuthenticationEventSender extends AuthenticationEventListenerRegistrar {

    void send( AuthenticationEvent ae );

    boolean isSendingEvents();
}
