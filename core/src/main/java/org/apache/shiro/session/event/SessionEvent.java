package org.apache.shiro.session.event;

import org.apache.shiro.event.ShiroEvent;
import org.apache.shiro.session.Session;

/**
 * @since 1.3
 */
public abstract class SessionEvent extends ShiroEvent {

    private final Session session;

    public SessionEvent(Session session) {
        super(session);
        this.session = session;
    }

    public Session getSession() {
        return session;
    }
}
