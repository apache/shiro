/*
 * Copyright (C) 2005 Les Hazlewood
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
import org.jsecurity.JSecurityException;
import org.jsecurity.authz.AuthorizationException;
import org.jsecurity.authz.HostUnauthorizedException;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.support.DefaultSessionFactory;
import org.jsecurity.web.WebSessionFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.beans.PropertyEditor;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Default JSecurity Reference Implementation of the {@link WebSessionFactory} interface.
 *
 * @since 0.1
 * @author Les Hazlewood
 */
public class DefaultWebSessionFactory extends DefaultSessionFactory implements WebSessionFactory {

    protected transient final Log log = LogFactory.getLog( getClass() );

    public static final String SESSION_ID_REQUEST_PARAM_NAME = "sessionId";

    /**
     * Session ID cookie will last a year by default.
     * <p>
     * This is ok, because the session expiration
     * will handle stopping a user from logging in with an old session.  We dont want
     * the cookie to expire before the session because then the user will have to log in again.
     * This would only occur if the user was using applets/webstart applications that updated
     * the session but not making web requests.  With an expiration time of one year, this
     * should never realistically happen.
     */
    protected static final int SESSION_ID_COOKIE_MAX_AGE = 60*60*24*365; // 1 year by default

    private String sessionIdRequestParamName = SESSION_ID_REQUEST_PARAM_NAME; //default;
    private String sessionIdCookieName = SESSION_ID_REQUEST_PARAM_NAME; //default;
    private String sessionIdHttpSessionKeyName = Session.class.getName() + "_HTTP_SESSION_KEY";
    private int sessionIdCookieMaxAge = SESSION_ID_COOKIE_MAX_AGE;

    private Class<? extends PropertyEditor> sessionIdEditorClass = UUIDEditor.class;

    private boolean validateRequestOrigin = false; //default

    public DefaultWebSessionFactory(){}

    public String getSessionIdRequestParamName() {
        return sessionIdRequestParamName;
    }

    public void setSessionIdRequestParamName( String sessionIdRequestParamName ) {
        this.sessionIdRequestParamName = sessionIdRequestParamName;
    }

    public String getSessionIdCookieName() {
        return sessionIdCookieName;
    }

    public void setSessionIdCookieName( String sessionIdCookieName ) {
        this.sessionIdCookieName = sessionIdCookieName;
    }

    public int getSessionIdCookieMaxAge() {
        return sessionIdCookieMaxAge;
    }

    public void setSessionIdCookieMaxAge( int sessionIdCookieMaxAge ) {
        this.sessionIdCookieMaxAge = sessionIdCookieMaxAge;
    }

    public String getSessionIdHttpSessionKeyName() {
        return sessionIdHttpSessionKeyName;
    }

    public void setSessionIdHttpSessionKeyName( String sessionIdHttpSessionKeyName ) {
        this.sessionIdHttpSessionKeyName = sessionIdHttpSessionKeyName;
    }

    public Class<? extends PropertyEditor> getSessionIdEditorClass() {
        return sessionIdEditorClass;
    }

    /**
     * If set to <tt>true</tt>, this <tt>WebSessionFactory</tt> will ensure that any
     * <tt>HttpRequest</tt> attempting
     * to join a session (i.e. via {@link #getSession getSession} must have the same
     * IP Address of the <tt>HttpRequest</tt> that started the session.
     *
     * <p> If set to <tt>false</tt>, any <tt>HttpRequest</tt> with a reference to a valid
     * session id may acquire that <tt>Session</tt>.
     *
     * <p>Although convenient, this should only be enabled in environments where the
     * system can <em>guarantee</em> that each IP address represents one and only one
     * machine accessing the system.
     *
     * <p>Public websites are not good candidates for enabling this
     * feature since many browser clients often sit behind NAT routers (in
     * which case many machines are viewed to come from the same IP, thereby making this
     * validation check useless).  Also, some internet service providers (e.g. AOL) may change a
     * client's IP in mid-session, making subsequent requests appear to come from a different
     * location.  Again, this feature should only be enabled where IP Addresses can be guaranteed a
     * 1-to-1 relationship with a user's session.
     *
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
     * a session.
     *
     * @see #isValidateRequestOrigin
     */
    public void setValidateRequestOrigin( boolean validateRequestOrigin ) {
        this.validateRequestOrigin = validateRequestOrigin;
    }

    /**
     * If set, an instance of this class will be used to convert a JSecurity
     * {@link Serializable Serializable} sessionId to a string value (and vice versa) when
     * reading and populating values in
     * {@link HttpServletRequest HttpServletRequest}s, {@link Cookie Cookie}s or
     * {@link HttpSession HttpSession}s.
     * @param clazz {@link PropertyEditor PropertyEditor} implementation used to
     * convert between string values and JSecurity sessionId objects.
     */
    public void setSessionIdEditorClass( Class<? extends PropertyEditor> clazz ) {
        this.sessionIdEditorClass = clazz;
    }

    protected InetAddress getInetAddress( HttpServletRequest request ) {
        InetAddress clientAddress = null;
        //get the Host/IP they're coming from:
        String addrString = request.getRemoteHost();
        try {
            clientAddress = InetAddress.getByName( addrString );
        } catch ( UnknownHostException e ) {
            if ( log.isWarnEnabled() ) {
                log.warn( "Unable to acquire InetAddress from HttpServletRequest", e );
            }
        }

        return clientAddress;
    }

    public Session start( HttpServletRequest request, HttpServletResponse response ) {
        InetAddress clientAddress = getInetAddress( request );
        Session session = start( clientAddress );
        Serializable sessionId = session.getSessionId();
        storeSessionIdInHttpSession( request, sessionId );
        storeSessionIdInCookie( response, sessionId );
        return session;
    }

    public Session getSession( HttpServletRequest request, HttpServletResponse response )
        throws InvalidSessionException, AuthorizationException {
        Session session = null;
        Serializable sessionId = getSessionId( request );
        if ( sessionId != null ) {
            session = getSession( sessionId );
            if ( isValidateRequestOrigin() ) {
                if ( log.isDebugEnabled() ) {
                    log.debug( "Validating request origin against session origin" );
                }
                validateSessionOrigin( request, session );
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No JSecurity session id associated with the given " +
                           "HttpServletRequest.  A Session will not be returned." );
            }
        }
        return session;
    }

    protected void validateSessionOrigin( HttpServletRequest request, Session session )
        throws HostUnauthorizedException {
        InetAddress requestIp = getInetAddress( request );
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

    protected Serializable getSessionId( HttpServletRequest request ) {
        Serializable sessionId = null;
        String sessionIdString = getSessionIdFromRequestParam( request );
        if ( sessionIdString == null ) {
            sessionIdString = getSessionIdFromCookie( request );
            if ( sessionIdString == null ) {
                sessionId = getSessionIdFromHttpSession( request );
                if ( log.isDebugEnabled() ) {
                    log.debug( "Unable to find JSecurity session id from request parameters, " +
                               "cookies, or inside the HttpSession.  All heuristics exhausted. " +
                               "Returning null session id");
                }
            }
        }

        if ( sessionIdString != null ) {
            sessionId = resolveSessionIdFromString( sessionIdString );
        }

        return sessionId;
    }

    protected String getSessionIdFromRequestParam( HttpServletRequest request ) {
        String paramName = getSessionIdRequestParamName();
        String param = request.getParameter( paramName );
        if ( param != null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Found JSecurity session id [" + param + "] from HttpServletRequest " +
                          "parameter [" + paramName + "]");
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No JSecurity session id found in the HttpServletRequest from " +
                           "request parameter named [" + paramName + "]" );
            }
        }

        return param;
    }

    /**
     * Returns the cookie with the given name from the request or <tt>null</tt> if no cookie
     * with that name could be found.
     * @param request the current executing http request.
     * @param cookieName the name of the cookie to find and return.
     * @return the cookie with the given name from the request or <tt>null</tt> if no cookie
     * with that name could be found.
     */
    private static Cookie getCookie(HttpServletRequest request, String cookieName) {
        Cookie cookies[] = request.getCookies();
        if (cookies != null) {
            for( Cookie cookie : cookies ) {
                if ( cookieName.equals( cookie.getName() ) ) {
                    return cookie;
                }
            }
        }
        return null;
    }

    protected String getSessionIdFromCookie( HttpServletRequest request ) {
        String sessionIdString = null;
        String cookieName = getSessionIdCookieName();
        Cookie cookie = getCookie( request, cookieName );
        if ( cookie != null ) {
            sessionIdString = cookie.getValue();
            if ( log.isInfoEnabled() ) {
                log.info( "Found JSecurity session id [" + sessionIdString + "] from " +
                          "HttpServletRequest Cookie [" + cookieName + "]" );
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No JSecurity session id found in request Cookies under " +
                           "cookie name [" + cookieName + "]" );
            }
        }

        return sessionIdString;
    }

    protected void storeSessionIdInCookie( HttpServletResponse response, Serializable sessionId ) {
        String cookieName = getSessionIdCookieName();
        int maxAge = getSessionIdCookieMaxAge();

        Cookie sessionIdCookie = new Cookie( cookieName, sessionId.toString() );

        sessionIdCookie.setMaxAge( maxAge );

        // We only want one cookie for the entire application, so set the path
        // to be "/" - otherwise it will create one cookie for every directory the
        // user navigates.
        sessionIdCookie.setPath( "/" );

        response.addCookie( sessionIdCookie );
        if ( log.isDebugEnabled() ) {
            log.debug( "Added Cookie [" + cookieName + "] with value [" + sessionId + "] " +
                       "to HttpServletResponse." );
        }
    }

    protected Serializable getSessionIdFromHttpSession( HttpServletRequest request ) {
        Serializable sessionId = null;
        String sessionKey = getSessionIdHttpSessionKeyName();

        HttpSession session = request.getSession( false );
        if ( session != null ) {
            sessionId = (Serializable)session.getAttribute( sessionKey );
        }

        if ( sessionId != null ) {
            if ( log.isInfoEnabled() ) {
                log.info( "Found JSecurity session id [" + sessionId + "] via " +
                          "HttpSession key [" + sessionKey + "]");
            }
        } else {
            if ( log.isDebugEnabled() ) {
                log.debug( "No JSecurity session id fround in HttpSession via " +
                           "session key [" + sessionKey + "]" );
            }
        }

        return sessionId;
    }

    protected void storeSessionIdInHttpSession( HttpServletRequest request, Serializable sessionId ) {
        String sessionKey = getSessionIdHttpSessionKeyName();

        HttpSession session = request.getSession();
        if ( session != null ) {
            session.setAttribute( sessionKey, sessionId );
            if ( log.isDebugEnabled() ) {
                log.debug( "Set HttpSession attribute [" + sessionKey + "] with value [" +
                           sessionId + "]" );
            }
        }
    }

    protected PropertyEditor newPropertyEditor( Class<? extends PropertyEditor> clazz ) {
        try {
            return clazz.newInstance();
        } catch ( Exception e ) {
            String msg = "Unable to instantiate PropertyEditor of type [" + clazz.getName() + "].";
            throw new JSecurityException( msg, e );
        }
    }

    /**
     * If the {@link #getSessionIdEditorClass() sessionIdEditorClass} is set, it will be used
     * to instantiate a new property editor and use that editor to convert the session id
     * string value to a JSecurity session id.
     * <p>If not set, the sessionId parameter (a String) will be returned.
     * @param sessionId JSecurity session id string value to convert to the actual
     * @return the Serializable representation of the sessionId string.
     */
    protected Serializable resolveSessionIdFromString( String sessionId ) {
        Class<? extends PropertyEditor> peClass = getSessionIdEditorClass();
        if ( peClass != null ) {
            PropertyEditor pe = newPropertyEditor( peClass );
            pe.setAsText( sessionId );
            return (Serializable)pe.getValue();
        }

        return sessionId;
    }


}
