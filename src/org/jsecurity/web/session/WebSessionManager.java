/*
 * Copyright (C) 2005-2008 Les Hazlewood
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
package org.jsecurity.web.session;

import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.mgt.DefaultSessionManager;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.SecurityWebSupport;
import org.jsecurity.web.attr.CookieAttribute;
import org.jsecurity.web.attr.RequestParamAttribute;
import org.jsecurity.web.attr.WebAttribute;
import org.jsecurity.web.servlet.JSecurityHttpServletRequest;
import org.jsecurity.web.servlet.JSecurityHttpSession;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;
import java.net.InetAddress;

/**
 * Web-application capable <tt>SessionManager</tt> implementation.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class WebSessionManager extends DefaultSessionManager {

    /**
     * Property specifying if, after a session object is acquired from the request, if that session should be
     * validated to ensure the starting origin of the session is the same as the incoming request.
     */
    private boolean validateRequestOrigin = false; //default

    protected CookieAttribute<Serializable> sessionIdCookieValue = null;
    protected RequestParamAttribute<Serializable> sessionIdRequestParamValue = null;

    public WebSessionManager() {
    }

    public CookieAttribute<Serializable> getSessionIdCookieValue() {
        return sessionIdCookieValue;
    }

    public void setSessionIdCookieValue( CookieAttribute<Serializable> sessionIdCookieValue) {
        this.sessionIdCookieValue = sessionIdCookieValue;
    }

    public RequestParamAttribute<Serializable> getSessionIdRequestParamValue() {
        return sessionIdRequestParamValue;
    }

    public void setSessionIdRequestParamValue( RequestParamAttribute<Serializable> sessionIdRequestParamValue) {
        this.sessionIdRequestParamValue = sessionIdRequestParamValue;
    }

    /**
     * If set to <tt>true</tt>, this implementation will ensure that any
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

    public void init() {
        super.init();
        ensureCookieSessionIdStore();
        ensureRequestParamSessionIdStore();
    }

    protected void ensureCookieSessionIdStore() {
        CookieAttribute<Serializable> cookieStore = getSessionIdCookieValue();
        if ( cookieStore == null ) {
            cookieStore = new CookieAttribute<Serializable>( JSecurityHttpSession.DEFAULT_SESSION_ID_NAME );
            cookieStore.setCheckRequestParams( false );
            setSessionIdCookieValue( cookieStore );
        }
    }

    protected void ensureRequestParamSessionIdStore() {
        RequestParamAttribute<Serializable> reqParamStore = getSessionIdRequestParamValue();
        if ( reqParamStore == null ) {
            reqParamStore = new RequestParamAttribute<Serializable>( JSecurityHttpSession.DEFAULT_SESSION_ID_NAME );
            setSessionIdRequestParamValue( reqParamStore );
        }
    }

    protected void validateSessionOrigin( ServletRequest request, Session session )
        throws HostUnauthorizedException {
        InetAddress requestIp = SecurityWebSupport.getInetAddress( request );
        InetAddress originIp = session.getHostAddress();
        Serializable sessionId = session.getId();

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

    protected void storeSessionId( Serializable currentId, ServletRequest request, ServletResponse response ) {
        if ( currentId == null ) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException( msg );
        }
        //ensure that the id has been set in the idStore, or if it already has, that it is not different than the
        //'real' session value:
        Serializable existingId = retrieveSessionId( request, response );
        if ( existingId == null || !currentId.equals( existingId ) ) {
            getSessionIdCookieValue().storeValue( currentId, request, response );
        }
    }

    protected Serializable retrieveSessionId( ServletRequest request, ServletResponse response ) {
        WebAttribute<Serializable> cookieSessionIdAttribute = getSessionIdCookieValue();
        Serializable id = cookieSessionIdAttribute.retrieveValue( request, response );
        if ( id != null ) {
            request.setAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                JSecurityHttpServletRequest.COOKIE_SESSION_ID_SOURCE );
        } else {
            id = getSessionIdRequestParamValue().retrieveValue( request, response );
            if ( id != null ) {
                request.setAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                    JSecurityHttpServletRequest.URL_SESSION_ID_SOURCE );
            }
        }
        return id;
    }

    public Serializable start(InetAddress hostAddress) throws HostUnauthorizedException, IllegalArgumentException {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        return start( request, response, hostAddress );
    }

    protected Serializable start( ServletRequest request, ServletResponse response, InetAddress inetAddress ) {
        Serializable sessionId = super.start( inetAddress );
        storeSessionId( sessionId, request, response );
        request.removeAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_ID_SOURCE );
        request.setAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE );
        return sessionId;
    }

    public Session doGetSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        if ( sessionId != null ) {
            return super.doGetSession( sessionId );
        } else {
            ServletRequest request = ThreadContext.getServletRequest();
            ServletResponse response = ThreadContext.getServletResponse();
            return getSession( request, response );
        }
    }

    /**
     * Returns the Session associated with the specified request if it is valid or <tt>null</tt> if a Session doesn't
     * exist or it was invalid.
     *
     * @param request  incoming servlet request
     * @param response outgoing servlet response
     * @return the Session associated with the incoming request or <tt>null</tt> if one does not exist.
     * @throws org.jsecurity.session.InvalidSessionException if the associated Session has expired prior to invoking this method.
     * @throws org.jsecurity.authz.AuthorizationException  if the caller is not authorized to access the session associated with the request.
     */
    public final Session getSession( ServletRequest request, ServletResponse response )
        throws InvalidSessionException, AuthorizationException {

        Session session;
        try {
            session = doGetSession( request, response );
        } catch ( InvalidSessionException ise ) {
            if ( log.isTraceEnabled() ) {
                log.trace( "Request Session is invalid, message: [" + ise.getMessage() + "]." );
            }
            session = handleInvalidSession( request, response, ise );
        }

        return session;
    }

    protected Session doGetSession( ServletRequest request, ServletResponse response ) {

        Session session = null;
        Serializable sessionId = retrieveSessionId( request, response );

        if ( sessionId != null ) {
            request.setAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_ID, sessionId );
            session = getSession( sessionId );
            if ( isValidateRequestOrigin() ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "Validating request origin against session origin" );
                }
                validateSessionOrigin( request, session );
            }
            if ( session != null ) {
                request.setAttribute( JSecurityHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE );
            }
        } else {
            if ( log.isTraceEnabled() ) {
                log.trace( "No JSecurity session id associated with the given " +
                    "HttpServletRequest.  A Session will not be returned." );
            }
        }

        return session;
    }

    protected Session handleInvalidSession( ServletRequest request,
                                            ServletResponse response,
                                            InvalidSessionException ise ) {
        if ( log.isTraceEnabled() ) {
            log.trace( "Sesssion associated with the current request is nonexistent or invalid.  Returning null.");
        }
        return null;
    }

}
