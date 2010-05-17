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

import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.ShiroHttpSession;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;


/**
 * Web-application capable {@link org.apache.shiro.session.mgt.SessionManager SessionManager} implementation.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultWebSessionManager extends DefaultSessionManager implements WebSessionManager {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSessionManager.class);

    private Cookie sessionIdCookie;
    private boolean sessionIdCookieEnabled;

    public DefaultWebSessionManager() {
        Cookie cookie = new SimpleCookie(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        cookie.setHttpOnly(true); //more secure, protects against XSS attacks
        this.sessionIdCookie = cookie;
        this.sessionIdCookieEnabled = true;
    }

    public Cookie getSessionIdCookie() {
        return sessionIdCookie;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdCookie(Cookie sessionIdCookie) {
        this.sessionIdCookie = sessionIdCookie;
    }

    public boolean isSessionIdCookieEnabled() {
        return sessionIdCookieEnabled;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdCookieEnabled(boolean sessionIdCookieEnabled) {
        this.sessionIdCookieEnabled = sessionIdCookieEnabled;
    }

    private void storeSessionId(Serializable currentId, ServletRequest request, ServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        if (!(request instanceof HttpServletRequest)) {
            log.debug("Current request is not an HttpServletRequest - cannot save session id cookie. Returning.");
            return;
        }
        Cookie template = getSessionIdCookie();
        Cookie cookie = new SimpleCookie(template);
        String idString = currentId.toString();
        cookie.setValue(idString);
        cookie.saveTo(WebUtils.toHttp(request), WebUtils.toHttp(response));
        log.trace("Set session ID cookie for session with id {}", idString);
    }

    private void markSessionIdValid(ServletRequest request) {
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
    }

    private void markSessionIdInvalid(ServletRequest request) {
        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
    }

    private void removeSessionIdCookie(ServletRequest request, ServletResponse response) {
        getSessionIdCookie().removeFrom(WebUtils.toHttp(request), WebUtils.toHttp(response));
    }

    private String getSessionIdCookieValue(ServletRequest request, ServletResponse response) {
        if (!isSessionIdCookieEnabled()) {
            log.debug("Session ID cookie is disabled - session id will not be acquired from a request cookie.");
            return null;
        }
        if (!(request instanceof HttpServletRequest)) {
            log.debug("Current request is not an HttpServletRequest - cannot get session ID cookie.  Returning null.");
            return null;
        }
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        return getSessionIdCookie().readValue(httpRequest, WebUtils.toHttp(response));
    }

    private Serializable getReferencedSessionId(ServletRequest request, ServletResponse response) {

        String id = getSessionIdCookieValue(request, response);
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                    ShiroHttpServletRequest.COOKIE_SESSION_ID_SOURCE);
        } else {
            //not in a cookie, or cookie is disabled - try the request params as a fallback (i.e. URL rewriting):
            id = request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
            if (id == null) {
                //try lowercase:
                id = request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME.toLowerCase());
            }
            if (id != null) {
                request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                        ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
            }
        }
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            //automatically mark it valid here.  If it is invalid, the
            //onUnknownSession method below will be invoked and we'll remove the attribute at that time.
            markSessionIdValid(request);
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
        ServletRequest request = WebUtils.getServletRequest();
        ServletResponse response = WebUtils.getServletResponse();
        if (request == null || response == null) {
            log.debug("Request or response object is not bound to the thread.  Assuming this session start " +
                    "activity is due to a non web request (possible in a web application that also services " +
                    "non web clients.");
            return;
        }
        if (isSessionIdCookieEnabled()) {
            Serializable sessionId = session.getId();
            storeSessionId(sessionId, request, response);
        } else {
            log.debug("Session ID cookie is disabled.  No cookie has been set for new session with id {}",
                    session.getId());
        }

        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
    }

    public Session getSession(ServletRequest request, ServletResponse response) throws SessionException {
        Serializable id = getReferencedSessionId(request, response);
        Session session = null;
        if ( id != null ) {
            session = getSession(id);
        }
        return session;
    }

    public Serializable getSessionId(ServletRequest request, ServletResponse response) {
        return getReferencedSessionId(request, response);
    }

    @Override
    public void onUnknownSession(Serializable sessionId) {
        ServletRequest request = WebUtils.getServletRequest();
        if (request != null) {
            markSessionIdInvalid(request);
        }
        removeSessionIdCookie();
    }

    protected void onStop(Session session) {
        super.onStop(session);
        removeSessionIdCookie();
    }

    protected void onExpiration(Session session) {
        super.onExpiration(session);
        removeSessionIdCookie();
    }

    private void removeSessionIdCookie() {
        ServletRequest request = WebUtils.getServletRequest();
        ServletResponse response = WebUtils.getServletResponse();
        if (request == null || response == null) {
            log.debug("No request or response bound to the thread.  Session ID cookie cannot be removed.  This could " +
                    "occur in a web application that also services non web clients (e.g. RMI remoting).");
            return;
        }
        removeSessionIdCookie(request, response);
    }
}
