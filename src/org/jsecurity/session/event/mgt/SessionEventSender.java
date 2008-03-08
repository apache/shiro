package org.jsecurity.session.event.mgt;

import org.jsecurity.session.event.SessionEvent;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface SessionEventSender extends SessionEventListenerRegistrar {
    
    void send( SessionEvent se );
    
    boolean isSendingEvents();
}
