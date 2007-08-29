/*
 * Copyright (C) 2005-2007 Les Hazlewood
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */
package org.jsecurity.web.support;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.SessionFactory;
import org.jsecurity.web.WebSessionFactory;
import org.jsecurity.web.WebStore;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.net.InetAddress;

/**
 * Default JSecurity implementation of the {@link WebSessionFactory} interface.
 * <p/>
 * <p>This SessionFactory implementation handles web-specific APIs and delegates session creation/acquisition
 * behavior to an underlying wrapped {@link SessionFactory SessionFactory} instance.
 *
 * @author Les Hazlewood
 * @since 0.1
 */
public class DefaultWebSessionFactory extends SecurityWebSupport implements WebSessionFactory {

    public static final String DEFAULT_SESSION_ID_KEY_NAME = "jsecSessionId";

    protected transient final Log log = LogFactory.getLog( getClass() );

    /**
     * Key that may be used for a http request or session attribute to alert that a referencing JSecurity Session
     * has expired.
     */
    public static final String EXPIRED_SESSION_KEY = SessionWebInterceptor.class.getName() + "_EXPIRED_SESSION_KEY";

    private boolean validateRequestOrigin = false; //default

    protected SessionFactory sessionFactory = null;

    //An HttpSessionStore is required if JSecurity sessions can be lazily created (e.g. SecurityContext.getSession())
    //after the response has started rendering - i.e. inside of a web controller or business-tier component accessed
    //after the web request comes in.
    //
    // Cookies can only be sent out before the response has started rendering, so saving a cookie
    //_after_ a response is done (as would happen in a web interceptor implementation's postHandle method) is
    // worthless, since the cookie would never be sent.
    //
    // As such, the only time a CookieStore can be used to store the JSecurity sessionId is if the
    // requireSessionOnRequest property is true, because a session would be created before the interceptor chain is
    // continued, where it is still 'legal' to modify the HTTP headers (i.e. set a Cookie).  If this property is set
    // to true in configuration (it is false by default), this implementation will automatically re-assign the
    // idStore attribute to be a CookieStore in the init() method.  If this property is false, the init method
    // will automatically create the HttpSessionStore.
    protected WebStore<Serializable> idStore = null;

    protected boolean requireSessionOnRequest = false;
    protected boolean createNewSessionWhenInvalid = true;
    protected boolean touchSessionOnRequest = false; //proactively touch the session on each request to ensure it is valid and timestamp has been updated.

    public DefaultWebSessionFactory(){}

    public DefaultWebSessionFactory( SessionFactory sessionFactory ) {
        setSessionFactory( sessionFactory );
    }

    public void setSessionFactory( SessionFactory sessionFactory ) {
        this.sessionFactory = sessionFactory;
    }

    public SessionFactory getSessionFactory() {
        return sessionFactory;
    }

    public WebStore<Serializable> getIdStore() {
        return idStore;
    }

    public void setIdStore( WebStore<Serializable> idStore ) {
        this.idStore = idStore;
    }

    /**
     * If set to <tt>true</tt>, this <tt>SessionWebInterceptor</tt> will ensure that any
     * <tt>HttpRequest</tt> attempting
     * to join a session (i.e. via {@link #getSession getSession} must have the same
     * IP Address of the <tt>HttpRequest</tt> that started the session.
     * <p/>
     * <p> If set to <tt>false</tt>, any <tt>HttpRequest</tt> with a reference to a valid
     * session id may acquire that <tt>Session</tt>.
     * <p/>
     * <p>Although convenient, this should only be enabled in environments where the
     * system can <em>guarantee</em> that each IP address represents one and only one
     * machine accessing the system.
     * <p/>
     * <p>Public websites are not good candidates for enabling this
     * feature since many browser clients often sit behind NAT routers (in
     * which case many machines are viewed to come from the same IP, thereby making this
     * validation check useless).  Also, some internet service providers (e.g. AOL) may change a
     * client's IP in mid-session, making subsequent requests appear to come from a different
     * location.  Again, this feature should only be enabled where IP Addresses can be guaranteed a
     * 1-to-1 relationship with a user's session.
     * <p/>
     * <p>For the reasons specified above, this property is <tt>false</tt> by default.
     *
     * @return true if this factory will verify each HttpRequest joining a session
     */
    public boolean isValidateRequestOrigin() {
        return validateRequestOrigin;
    }

    /**
     * Sets whether or not a request's origin will be validated when accessing a session.  See
     * the {@link #isValidateRequestOrigin} JavaDoc for an in-depth explanation of this property.
     *
     * @param validateRequestOrigin whether or not to validate the request's origin when accessing
     *                              a session.
     * @see #isValidateRequestOrigin
     */
    public void setValidateRequestOrigin( boolean validateRequestOrigin ) {
        this.validateRequestOrigin = validateRequestOrigin;
    }

    public boolean isRequireSessionOnRequest() {
        return requireSessionOnRequest;
    }

    public void setRequireSessionOnRequest( boolean requireSessionOnRequest ) {
        this.requireSessionOnRequest = requireSessionOnRequest;
    }

    public boolean isCreateNewSessionWhenInvalid() {
        return createNewSessionWhenInvalid;
    }

    public void setCreateNewSessionWhenInvalid( boolean createNewSessionWhenInvalid ) {
        this.createNewSessionWhenInvalid = createNewSessionWhenInvalid;
    }

    /**
     * Returns if this WebSessionFactory will proactively {@link Session#touch() touch} a session on every
     * request to ensure it is valid and its access timestamp has been updated.
     * <p/>
     * <p>The default value is <tt>false</tt>, since most appliacations actively update their session objects enough
     * such that the session does not time out.
     * <p/>
     * <p>However, if you want to ensure that a session is valid on every request
     * such that the Session's last access timestamp shows the last time they interacted with the web application,
     * you will probably want to set this attribute to <tt>true</tt>.
     *
     * @return if this WebSessionFactory will proactively {@link Session#touch() touch} a session on every
     *         request to ensure it is valid and its access timestamp has been updated.
     */
    public boolean isTouchSessionOnRequest() {
        return touchSessionOnRequest;
    }

    public void setTouchSessionOnRequest( boolean touchSessionOnRequest ) {
        this.touchSessionOnRequest = touchSessionOnRequest;
    }

    protected void assertSessionFactory() {
        if ( getSessionFactory() == null ) {
            String msg = "sessionFactory property must be set.";
            throw new IllegalStateException( msg );
        }
    }

    public void init() {
        assertSessionFactory();
        WebStore<Serializable> store = getIdStore();
        if ( store == null ) {
            if ( isRequireSessionOnRequest() ) {
                store = new CookieStore<Serializable>( DEFAULT_SESSION_ID_KEY_NAME, CookieStore.INDEFINITE );
            } else {
                store = new HttpSessionStore<Serializable>( DEFAULT_SESSION_ID_KEY_NAME );
            }
            setIdStore( store );
        }
    }

    protected void validateSessionOrigin( HttpServletRequest request, Session session )
        throws HostUnauthorizedException {
        InetAddress requestIp = SecurityWebSupport.getInetAddress( request );
        InetAddress originIp = session.getHostAddress();
        Serializable sessionId = session.getSessionId();

        if ( originIp == null ) {
            if ( requestIp != null ) {
                String msg = "No IP Address was specified when creating session with id [" +
                    sessionId + "].  Attempting to access session from " +
                    "IP [" + requestIp + "].  Origin IP and request IP must match.";
                throw new HostUnauthorizedException( msg );
            }
        } else {
            if ( requestIp != null ) {
                if ( !requestIp.equals( originIp ) ) {
                    String msg = "Session with id [" + sessionId + "] originated from [" +
                        originIp + "], but the current HttpServletRequest originated " +
                        "from [" + requestIp + "].  Disallowing session access: " +
                        "session origin and request origin must match to allow access.";
                    throw new HostUnauthorizedException( msg );
                }

            } else {
                String msg = "No IP Address associated with the current HttpServletRequest.  " +
                    "Session with id [" + sessionId + "] originated from " +
                    "[" + originIp + "].  Request IP must match the session's origin " +
                    "IP in order to gain access to that session.";
                throw new HostUnauthorizedException( msg );
            }
        }
    }

    protected void storeSessionId( Session session, HttpServletRequest request, HttpServletResponse response ) {
        Serializable currentId = session.getSessionId();
        if ( currentId == null ) {
            String msg = "Session#getSessionId() cannot return null when storing sessions for subsequent requests.";
            throw new IllegalStateException( msg );
        }
        //ensure that the id has been set in the idStore, or if it already has, that it is not different than the
        //'real' session value:
        Serializable existingId = retrieveSessionId( request, response );
        if ( existingId == null || !currentId.equals( existingId ) ) {
            getIdStore().storeValue( currentId, request, response );
        }
    }

    protected Serializable retrieveSessionId( HttpServletRequest request, HttpServletResponse response ) {
        return getIdStore().retrieveValue( request, response );
    }

    public Session getSession( Serializable sessionId ) throws InvalidSessionException, AuthorizationException {
        assertSessionFactory();
        return sessionFactory.getSession( sessionId );
    }

    protected Session handleInvalidSession( HttpServletRequest request,
                                            HttpServletResponse response,
                                            InvalidSessionException ise ) {
        if ( log.isTraceEnabled() ) {
            log.trace( "Handling invalid session associated with the request." );
        }
        Session session = null;

        if ( isRequireSessionOnRequest() || isCreateNewSessionWhenInvalid() ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Configured to create a new session on invalid session - attempting to start a new session..." );
            }
            session = start( request, response );
            if ( log.isTraceEnabled() ) {
                log.trace( "New session started successfully." );
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "Configured to _not_ start a new session after an invalid session - returning a null session." );
            }
        }

        if ( log.isTraceEnabled() ) {
            log.trace( "Adding EXPIRED_SESSION_KEY as a request attribute to alert that the request's incoming " +
                "referenced session had expired." );
        }
        request.setAttribute( EXPIRED_SESSION_KEY, Boolean.TRUE );

        return session;
    }


    protected Session doGetSession( HttpServletRequest request, HttpServletResponse response ) {

        Session session = null;
        Serializable sessionId = retrieveSessionId( request, response );

        if ( sessionId != null ) {
            assertSessionFactory();
            session = sessionFactory.getSession( sessionId );
            if ( isValidateRequestOrigin() ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "Validating request origin against session origin" );
                }
                validateSessionOrigin( request, session );
            }
        } else {
            if ( log.isWarnEnabled() ) {
                log.warn( "No JSecurity session id associated with the given " +
                    "HttpServletRequest.  A Session will not be returned." );
            }
        }
        return session;


    }

    /**
     * Acquires a session for the given request, and if there isn't one, automatically creates one and makes it
     * accessible for future requests.
     * 
     * @param request incoming servlet request
     * @param response outgoing servlet response
     * @return the Session associated with the incoming request, if any.
     */
    public final Session getSession( HttpServletRequest request, HttpServletResponse response )
        throws InvalidSessionException, AuthorizationException {

        Session session;

        try {
            session = doGetSession( request, response );
            if ( session == null ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "No JSecurity Session associated with the HttpServletRequest." );
                }
                if ( isRequireSessionOnRequest() ) {
                    if ( log.isDebugEnabled() ) {
                        log.debug( "JSecurity Sessions are required for each request (per the " +
                            "isRequireSessionOnRequest() attribute) - Attempting to start a new session..." );
                    }
                    session = start( request, response );
                    if ( log.isDebugEnabled() ) {
                        log.debug( "Created new JSecurity Session with id [" + session.getSessionId() + "]" );
                    }
                }
            } else {
                if ( isTouchSessionOnRequest() ) {
                    session.touch();
                }
            }
        } catch ( InvalidSessionException ise ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Request JSecurity Session is invalid, message: [" + ise.getMessage() + "]." );
            }
            session = handleInvalidSession( request, response, ise );
        }

        return session;
    }

    public Session start( HttpServletRequest request, HttpServletResponse response ) {
        InetAddress clientAddress = SecurityWebSupport.getInetAddress( request );
        Session session = getSessionFactory().start( clientAddress );
        //ensure it is available for future requests:
        storeSessionId( session, request, response );
        return session;
    }
}
