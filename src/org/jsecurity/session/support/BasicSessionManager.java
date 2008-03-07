package org.jsecurity.session.support;

import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.ExpiredSessionException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;

import java.io.Serializable;
import java.net.InetAddress;
import java.util.Collection;
import java.util.Date;

/**
 * @since 0.9
 * @author Les Hazlewood
 */
public abstract class BasicSessionManager extends EventCapableSessionManager {

    public Serializable start(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        Session session = createSession(originatingHost);
        sendStartEvent(session);
        return session.getSessionId();
    }

    protected abstract Session createSession( InetAddress originatingHost ) throws HostUnauthorizedException, IllegalArgumentException;

    protected abstract Session getSession( Serializable sessionId ) throws InvalidSessionException;

    public Date getStartTimestamp(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public Date getStopTimestamp(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public Date getLastAccessTime(Serializable sessionId) {
        return getSession(sessionId).getStartTimestamp();
    }

    public boolean isStopped(Serializable sessionId) {
        Session session = getSession(sessionId);
        return session.isExpired() || session.getStopTimestamp() != null;
    }

    public boolean isExpired(Serializable sessionId) {
        try {
            Session session = getSession(sessionId);
            return session.isExpired();
        } catch (ExpiredSessionException e) {
            return true;
        }
    }

    public long getTimeout(Serializable sessionId) throws InvalidSessionException {
        return getSession(sessionId).getTimeout();
    }

    public void setTimeout(Serializable sessionId, long maxIdleTimeInMillis) throws InvalidSessionException {
        getSession(sessionId).setTimeout(maxIdleTimeInMillis);
    }

    public void touch(Serializable sessionId) throws InvalidSessionException {
        getSession(sessionId).touch();
    }

    public InetAddress getHostAddress(Serializable sessionId) {
        return getSession(sessionId).getHostAddress();
    }

    public void stop(Serializable sessionId) throws InvalidSessionException {
        Session session = getSession(sessionId);
        stop(session);
    }

    protected void stop( Session session ) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Stopping session with id [" + session.getSessionId() + "]" );
        }
        sendStopEvent(session);
        session.stop();
        onStop( session );
    }

    /**
     * Subclasses should override this method to update the state of the given
     * {@link Session} implementation prior to updating the EIS with the stopped object.
     * @param session the session object to update w/ data related to being stopped.
     */
    protected void onStop( Session session ){}

    public Collection<Object> getAttributeKeys(Serializable sessionId) {
        return getSession(sessionId).getAttributeKeys();
    }

    public Object getAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return getSession(sessionId).getAttribute(key);
    }

    public void setAttribute(Serializable sessionId, Object key, Object value) throws InvalidSessionException {
        getSession(sessionId).setAttribute(key, value);
    }

    public Object removeAttribute(Serializable sessionId, Object key) throws InvalidSessionException {
        return getSession(sessionId).removeAttribute(key);
    }
}
