package org.jsecurity.web.support;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;

/**
 * TODO class JavaDoc
 *
 * @since 0.2
 * 
 * @author Les Hazlewood
 */
public abstract class AbstractWebSessionFactory extends SecurityWebSupport implements WebSessionFactory {

    private boolean enforceSessionOnGet = false;

    /**
     * Returns the current session enforcement policy for the
     * {@link #getSession(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     * method - please see that method's JavaDoc for usage information.
     *
     * <p>The default value is <tt>false</tt>.
     *
     * @return the current session enforcement policy for the {@link #getSession(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method.
     *
     */
    public boolean isEnforceSessionOnGet() {
        return enforceSessionOnGet;
    }

    /**
     * Specifies session enforcemnt policy for the {@link #getSession(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     * method - please see that method's JavaDoc for usage information.
     *
     * <p>The default value is <tt>false</tt>.
     *
     * @param enforceSessionOnGet the session enforcement policy for the {@link #getSession(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method.
     */
    public void setEnforceSessionOnGet( boolean enforceSessionOnGet ) {
        this.enforceSessionOnGet = enforceSessionOnGet;
    }

    protected Session handleInvalidSession( ServletRequest request,
                                            ServletResponse response,
                                            InvalidSessionException ise ) {
        if ( log.isTraceEnabled() ) {
            log.trace( "Handling invalid session associated with the request." );
        }

        Session session = null;

        if ( isEnforceSessionOnGet() ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Configured to create a new session on invalid session - attempting to start a new session..." );
            }
            session = start( request, response );
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "Configured to _not_ start a new session after an invalid session - returning null." );
            }
        }


        return session;
    }

    protected abstract Session doGetSession( ServletRequest request, ServletResponse response );


    /**
     * Returns the Session associated with the specified request, <tt>null</tt>, or a new Session, depending on the
     * enforcement policy in effect as specified by the {@link #setEnforceSessionOnGet(boolean) enforceSessionOnGet}
     * property.
     *
     * <p>This method implementation functions as follows:</p>
     *
     * <ol>
     *   <li>If the the incoming <tt>request</tt> references a valid, non-expired session, it will be returned
     *       immediately</li>
     *   <li>If the incoming <tt>request</tt> references an invalid, expired, or non-existent Session, and the
     *       <tt>enforceSessionOnGet</tt> property is <tt>true</tt>, then a new Session will be created via the
     *       {@link #start(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method and returned.</li>
     *   <li>If the incoming <tt>request</tt> references an invalid, expired or non-existent Session, and the
     *       <tt>enforceSessionOnGet</tt> property is <tt>false</tt>, then <tt>null</tt> is returned.</li>
     * </ol>
     *
     * <p>The default value of <tt>enforceSessionOnGet</tt> is <tt>true</tt> to guarantee a Session for an
     * HttpRequest if one is desired.
     *
     * @param request  incoming servlet request
     * @param response outgoing servlet response
     * @return the Session associated with the incoming request, <tt>null</tt> or a new Session, depending on the
     * {@link #setEnforceSessionOnGet(boolean) enforceSessionOnGet} policy in effect.
     * @throws InvalidSessionException if the associated Session has expired prior to invoking this method.
     * @throws org.jsecurity.authz.AuthorizationException  if the caller is not authorized to access the session associated with the request.
     */
    public final Session getSession( ServletRequest request, ServletResponse response )
        throws InvalidSessionException, AuthorizationException {

        Session session = null;
        try {
            session = doGetSession( request, response );
            if ( session == null && isEnforceSessionOnGet() ) {
                session = start( request, response );
            }
        } catch ( InvalidSessionException ise ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Request JSecurity Session is invalid, message: [" + ise.getMessage() + "]." );
            }
            session = handleInvalidSession( request, response, ise );
        }

        return session;
    }

    protected abstract Session start( ServletRequest request, ServletResponse response, InetAddress inetAddress );

    /**
     * Starts a brand new Session, associates it with the specified request, and makes that session available for
     * future requests via a Cookie or URL rewriting as specified by the Servlet Specification.
     *
     * @param request incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return a new Session for the specified request/response pair.
     */
    public Session start( ServletRequest request, ServletResponse response ) {
        InetAddress clientAddress = SecurityWebSupport.getInetAddress( request );
        Session s = start( request, response, clientAddress );
        if ( log.isTraceEnabled() ) {
            log.trace( "Started new JSecurity Session with id [" + s.getSessionId() );
        }
        return s;
    }

}
