/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.shiro.web.session;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.HostUnauthorizedException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.attr.CookieAttribute;
import org.apache.shiro.web.attr.RequestParamAttribute;
import org.apache.shiro.web.attr.WebAttribute;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.ShiroHttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
public class DefaultWebSessionManager extends DefaultSessionManager implements WebSessionManager {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSessionManager.class);

    /**
     * Property specifying if, after a session object is acquired from the request, if that session should be
     * validated to ensure the starting origin of the session is the same as the incoming request.
     */
    private boolean validateRequestOrigin = false; //default

    protected CookieAttribute<Serializable> sessionIdCookieAttribute = null;
    protected RequestParamAttribute<Serializable> sessionIdRequestParamAttribute = null;

    public DefaultWebSessionManager() {
        ensureCookieSessionIdStore();
        ensureRequestParamSessionIdStore();
    }

    public CookieAttribute<Serializable> getSessionIdCookieAttribute() {
        return sessionIdCookieAttribute;
    }

    public void setSessionIdCookieAttribute(CookieAttribute<Serializable> sessionIdCookieAttribute) {
        this.sessionIdCookieAttribute = sessionIdCookieAttribute;
    }

    public RequestParamAttribute<Serializable> getSessionIdRequestParamAttribute() {
        return sessionIdRequestParamAttribute;
    }

    public void setSessionIdRequestParamAttribute(RequestParamAttribute<Serializable> sessionIdRequestParamAttribute) {
        this.sessionIdRequestParamAttribute = sessionIdRequestParamAttribute;
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
    public void setValidateRequestOrigin(boolean validateRequestOrigin) {
        this.validateRequestOrigin = validateRequestOrigin;
    }

    public void setSessionIdCookieName(String name) {
        getSessionIdCookieAttribute().setName(name);
    }

    public void setSessionIdCookieDomain(String domain) {
        getSessionIdCookieAttribute().setDomain(domain);
    }

    public void setSessionIdCookiePath(String path) {
        getSessionIdCookieAttribute().setPath(path);
    }

    public void setSessionIdCookieMaxAge(int maxAge) {
        getSessionIdCookieAttribute().setMaxAge(maxAge);
    }

    public void setSessionIdCookieVersion(int version) {
        getSessionIdCookieAttribute().setVersion(version);
    }

    public void setSessionIdCookieSecure(boolean secure) {
        getSessionIdCookieAttribute().setSecure(secure);
    }

    public void setSessionIdCookieComment(String comment) {
        getSessionIdCookieAttribute().setComment(comment);
    }

    protected void ensureCookieSessionIdStore() {
        CookieAttribute<Serializable> cookieStore = getSessionIdCookieAttribute();
        if (cookieStore == null) {
            cookieStore = new CookieAttribute<Serializable>(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
            cookieStore.setCheckRequestParams(false);
            setSessionIdCookieAttribute(cookieStore);
        }
    }

    protected void ensureRequestParamSessionIdStore() {
        RequestParamAttribute<Serializable> reqParamStore = getSessionIdRequestParamAttribute();
        if (reqParamStore == null) {
            reqParamStore = new RequestParamAttribute<Serializable>(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
            setSessionIdRequestParamAttribute(reqParamStore);
        }
    }

    protected void validateSessionOrigin(ServletRequest request, Session session)
            throws HostUnauthorizedException {
        InetAddress requestIp = WebUtils.getInetAddress(request);
        InetAddress originIp = session.getHostAddress();
        Serializable sessionId = session.getId();

        if (originIp == null) {
            if (requestIp != null) {
                String msg = "No IP Address was specified when creating session with id [" +
                        sessionId + "].  Attempting to access session from " +
                        "IP [" + requestIp + "].  Origin IP and request IP must match.";
                throw new HostUnauthorizedException(msg);
            }
        } else {
            if (requestIp != null) {
                if (!requestIp.equals(originIp)) {
                    String msg = "Session with id [" + sessionId + "] originated from [" +
                            originIp + "], but the current HttpServletRequest originated " +
                            "from [" + requestIp + "].  Disallowing session access: " +
                            "session origin and request origin must match to allow access.";
                    throw new HostUnauthorizedException(msg);
                }

            } else {
                String msg = "No IP Address associated with the current HttpServletRequest.  " +
                        "Session with id [" + sessionId + "] originated from " +
                        "[" + originIp + "].  Request IP must match the session's origin " +
                        "IP in order to gain access to that session.";
                throw new HostUnauthorizedException(msg);
            }
        }
    }

    protected void storeSessionId(Serializable currentId, ServletRequest request, ServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        //ensure that the id has been set in the idStore, or if it already has, that it is not different than the
        //'real' session value:
        Serializable existingId = getReferencedSessionId(request, response);
        if (existingId == null || !currentId.equals(existingId)) {
            getSessionIdCookieAttribute().storeValue(currentId, request, response);
        }
    }

    private void markSessionIdValid(Serializable sessionId, ServletRequest request) {
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
    }

    private void removeSessionIdCookie(ServletRequest request, ServletResponse response) {
        getSessionIdCookieAttribute().removeValue(request, response);
    }


    protected Serializable getReferencedSessionId(ServletRequest request, ServletResponse response) {
        WebAttribute<Serializable> cookieSessionIdAttribute = getSessionIdCookieAttribute();
        Serializable id = cookieSessionIdAttribute.retrieveValue(request, response);
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                    ShiroHttpServletRequest.COOKIE_SESSION_ID_SOURCE);
        } else {
            id = getSessionIdRequestParamAttribute().retrieveValue(request, response);
            if (id != null) {
                request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                        ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
            }
        }
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        }
        return id;
    }

    /**
     * Stores the Session's ID, usually as a Cookie, to associate with future requests.
     *
     * @param session the session that was just {@link #createSession created}.
     */
    @Override
    protected void onStart(Session session) {
        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        onStart(session, request, response);
    }

    protected void onStart(Session session, ServletRequest request, ServletResponse response) {
        Serializable sessionId = session.getId();
        storeSessionId(sessionId, request, response);
        onSessionStart(request);
    }

    protected void onSessionStart(ServletRequest request) {
        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
    }

    @Override
    protected Session retrieveSession(Serializable sessionId) throws InvalidSessionException, AuthorizationException {
        if (sessionId == null) {
            ServletRequest request = WebUtils.getRequiredServletRequest();
            ServletResponse response = WebUtils.getRequiredServletResponse();
            return getSession(request, response);
        }
        return retrieveSessionFromDataSource(sessionId);
    }

    /**
     * Returns the Session associated with the specified request if it is valid or <tt>null</tt> if a Session doesn't
     * exist or it was invalid.
     *
     * @param request  incoming servlet request
     * @param response outgoing servlet response
     * @return the Session associated with the incoming request or <tt>null</tt> if one does not exist.
     * @throws org.apache.shiro.authz.AuthorizationException
     *          if the caller is not authorized to access the session associated with the request.
     */
    public Session getSession(ServletRequest request, ServletResponse response)
            throws InvalidSessionException, AuthorizationException {

        Session session = null;
        Serializable sessionId = getReferencedSessionId(request, response);

        if (sessionId != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, sessionId);
            try {
                session = retrieveSessionFromDataSource(sessionId);
                markSessionIdValid(sessionId, request);
            } catch (InvalidSessionException ise) {
                if (log.isTraceEnabled()) {
                    log.trace("Request Session with id [" + ise.getSessionId() + "] is invalid, message: [" +
                            ise.getMessage() + "].  Removing any associated session cookie...");
                }
                removeSessionIdCookie(request, response);
                //give subclass a chance to do something additional if necessary.  Otherwise returning null is just fine:
                session = handleInvalidSession(request, response, ise);
            }
            if (isValidateRequestOrigin()) {
                if (log.isDebugEnabled()) {
                    log.debug("Validating request origin against session origin");
                }
                validateSessionOrigin(request, session);
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("A valid Shiro session id was not associated with the current request.");
            }
        }

        return session;
    }

    protected Session handleInvalidSession(ServletRequest request,
                                           ServletResponse response,
                                           InvalidSessionException ise) {
        if (log.isTraceEnabled()) {
            log.trace("Sesssion associated with the current request is nonexistent or invalid.  Returning null.");
        }
        return null;
    }

    protected void onStop(Session session) {
        super.onStop(session);
        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        removeSessionIdCookie(request, response);
        getSessionIdCookieAttribute().removeValue(request, response);
    }
}
