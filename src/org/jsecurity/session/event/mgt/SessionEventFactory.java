package org.jsecurity.session.event.mgt;

import org.jsecurity.session.Session;
import org.jsecurity.session.event.SessionEvent;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface SessionEventFactory {

    SessionEvent createStartEvent( Session session );

    SessionEvent createStopEvent( Session session );

    SessionEvent createExpirationEvent( Session session );

}
