package org.apache.shiro.session.event;

import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SessionKey;

/**
 * @since 1.3
 */
public class InvalidSessionEvent extends SessionEvent {

    private final SessionKey sessionKey;
    private final InvalidSessionException exception;

    public InvalidSessionEvent(Session session, SessionKey sessionKey, InvalidSessionException exception) {
        super(session);
        this.sessionKey = sessionKey;
        this.exception = exception;
    }

    public SessionKey getSessionKey() {
        return sessionKey;
    }

    public InvalidSessionException getException() {
        return exception;
    }

    public boolean isSessionExpired() {
        return exception instanceof ExpiredSessionException;
    }
}
