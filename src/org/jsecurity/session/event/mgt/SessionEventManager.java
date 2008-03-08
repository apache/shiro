package org.jsecurity.session.event.mgt;

import org.jsecurity.session.Session;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public interface SessionEventManager extends SessionEventFactory, SessionEventSender {

    void sendStartEvent(Session session);

    void sendStopEvent(Session session);

    void sendExpirationEvent(Session session);

}
