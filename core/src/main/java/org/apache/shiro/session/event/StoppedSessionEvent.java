package org.apache.shiro.session.event;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionKey;

/**
 * @since 1.3
 */
public class StoppedSessionEvent extends SessionEvent {

    private final SessionKey sessionKey;

    public StoppedSessionEvent(Session session, SessionKey sessionKey) {
        super(session);
        this.sessionKey = sessionKey;
    }

    public SessionKey getSessionKey() {
        return sessionKey;
    }
}
