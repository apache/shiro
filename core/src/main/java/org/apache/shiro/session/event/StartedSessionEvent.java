package org.apache.shiro.session.event;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionContext;

/**
 * @since 1.3
 */
public class StartedSessionEvent extends SessionEvent {

    private final SessionContext sessionContext;

    public StartedSessionEvent(Session session, SessionContext sessionContext) {
        super(session);
        this.sessionContext = sessionContext;
    }

    public SessionContext getSessionContext() {
        return sessionContext;
    }
}
