package org.jsecurity.ri.session;

import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.ri.session.SessionManager;
import org.jsecurity.session.Session;
import org.jsecurity.ri.session.SessionHandle;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.ExpiredSessionException;
import org.jsecurity.session.StoppedSessionException;

import java.net.InetAddress;
import java.io.Serializable;

/**
 * Default JSecurity reference implementation of a {@link org.jsecurity.session.SessionFactory}.  This implementation
 * returns instances where all methods delegate to a corresponding
 * {@link org.jsecurity.ri.session.SessionManager SessionManager} method call.  That is, the objects returned act as
 * transparent proxies to the SessionManager responsible for all Sessions in a system.
 *
 * <p>Objects returned from this factory implementation should not be cached on the
 * business/server tier (e.g. in an HttpSession or in some local {@link java.util.Map Map} instance).
 * All instances should be acquired from this {@link org.jsecurity.session.SessionFactory SessionFactory} at the
 * beginning of a thread's exucution, such as at the beginning of a remote method invocation or at
 * the beginning of an Http request.  They are extremely lightweight and are designed to be created
 * as needed.
 *
 * <p>This transparent proxy/delegate technique allows the JSecurity reference implementation to
 * maintain a stateless architecture (i.e. similar to accessing a Stateless Session Bean EJB),
 * which is extremely efficient.  Any state to be maintained is the responsibility of the
 * SessionManager, not your application, thereby aking your code much cleaner and more efficient.
 *
 * @author Les Hazlewood
 */
public class DefaultSessionFactory implements SessionFactory {

    private SessionManager sessionManager = null;

    public DefaultSessionFactory(){}

    public void setSessionManager( SessionManager sessionManager ) {
        this.sessionManager = sessionManager;
    }

    public void init() {
        if ( this.sessionManager == null ) {
            String msg = "sessionManager property must be set";
            throw new IllegalStateException( msg );
        }
    }

    public Session start( InetAddress hostAddress )
        throws HostUnauthorizedException, IllegalArgumentException {

        Serializable sessionId = sessionManager.start( hostAddress );
        return new SessionHandle( sessionManager, sessionId );
    }

    public Session getSession( Serializable sessionId )
        throws InvalidSessionException, AuthorizationException {

        if ( sessionManager.isExpired( sessionId ) ) {
            String msg = "Session with id [" + sessionId + "] has expired and may not " +
                         "be used.";
            throw new ExpiredSessionException( msg );
        } else if ( sessionManager.isStopped( sessionId ) ) {
            String msg = "Session with id [" + sessionId + "] has been stopped and may not " +
                         "be used.";
            throw new StoppedSessionException( msg );
        }

        return new SessionHandle( sessionManager, sessionId );
    }

}
