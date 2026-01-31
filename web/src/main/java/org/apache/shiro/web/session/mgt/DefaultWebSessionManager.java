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
package org.apache.shiro.web.session.mgt;

import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.DelegatingSession;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.ShiroHttpSession;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.Serializable;


/**
 * Web-application capable {@link org.apache.shiro.session.mgt.SessionManager SessionManager} implementation.
 *
 * @since 0.9
 */
public class DefaultWebSessionManager extends DefaultSessionManager implements WebSessionManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultWebSessionManager.class);

    private Cookie sessionIdCookie;
    private boolean sessionIdCookieEnabled;
    private boolean sessionIdUrlRewritingEnabled;

    public DefaultWebSessionManager() {
        Cookie cookie = new SimpleCookie(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        //more secure, protects against XSS attacks
        cookie.setHttpOnly(true);
        this.sessionIdCookie = cookie;
        this.sessionIdCookieEnabled = true;
        this.sessionIdUrlRewritingEnabled = false;
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

    public boolean isSessionIdUrlRewritingEnabled() {
        return sessionIdUrlRewritingEnabled;
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public void setSessionIdUrlRewritingEnabled(boolean sessionIdUrlRewritingEnabled) {
        this.sessionIdUrlRewritingEnabled = sessionIdUrlRewritingEnabled;
    }

    private void storeSessionId(Serializable currentId, HttpServletRequest request, HttpServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        Cookie template = getSessionIdCookie();
        Cookie cookie = new SimpleCookie(template);
        String idString = currentId.toString();
        cookie.setValue(idString);
        cookie.saveTo(request, response);
        LOGGER.trace("Set session ID cookie for session with id {}", idString);
    }

    private void removeSessionIdCookie(HttpServletRequest request, HttpServletResponse response) {
        getSessionIdCookie().removeFrom(request, response);
    }

    private String getSessionIdCookieValue(ServletRequest request, ServletResponse response) {
        if (!isSessionIdCookieEnabled()) {
            LOGGER.debug("Session ID cookie is disabled - session id will not be acquired from a request cookie.");
            return null;
        }
        if (!(request instanceof HttpServletRequest)) {
            LOGGER.debug("Current request is not an HttpServletRequest - cannot get session ID cookie.  Returning null.");
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
            //not in a cookie, or cookie is disabled - try the request URI as a fallback (i.e. due to URL rewriting):

            //try the URI path segment parameters first:
            id = getUriPathSegmentParamValue(request, ShiroHttpSession.DEFAULT_SESSION_ID_NAME);

            if (id == null && request instanceof HttpServletRequest) {
                //not a URI path segment parameter, try the query parameters:
                String name = getSessionIdName();
                HttpServletRequest httpServletRequest = WebUtils.toHttp(request);
                String queryString = httpServletRequest.getQueryString();
                if (queryString != null && queryString.contains(name)) {
                    id = request.getParameter(name);
                }
                if (id == null && queryString != null && queryString.contains(name.toLowerCase())) {
                    //try lowercase:
                    id = request.getParameter(name.toLowerCase());
                }
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
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        }

        // always set rewrite flag - SHIRO-361
        request.setAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED, isSessionIdUrlRewritingEnabled());

        return id;
    }

    //SHIRO-351
    //also see http://cdivilly.wordpress.com/2011/04/22/java-servlets-uri-parameters/
    //since 1.2.2
    private String getUriPathSegmentParamValue(ServletRequest servletRequest, String paramName) {

        if (!(servletRequest instanceof HttpServletRequest)) {
            return null;
        }
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String uri = request.getRequestURI();
        if (uri == null) {
            return null;
        }

        int queryStartIndex = uri.indexOf('?');
        //get rid of the query string
        if (queryStartIndex >= 0) {
            uri = uri.substring(0, queryStartIndex);
        }

        //now check for path segment parameters:
        int index = uri.indexOf(';');
        if (index < 0) {
            //no path segment params - return:
            return null;
        }

        //there are path segment params, let's get the last one that may exist:
        final String token = paramName + "=";

        //uri now contains only the path segment params
        uri = uri.substring(index + 1);

        //we only care about the last JSESSIONID param:
        index = uri.lastIndexOf(token);
        if (index < 0) {
            //no segment param:
            return null;
        }

        uri = uri.substring(index + token.length());

        //strip off any remaining segment params:
        index = uri.indexOf(';');
        if (index >= 0) {
            uri = uri.substring(0, index);
        }

        //what remains is the value
        return uri;
    }

    //since 1.2.1
    private String getSessionIdName() {
        String name = this.sessionIdCookie != null ? this.sessionIdCookie.getName() : null;
        if (name == null) {
            name = ShiroHttpSession.DEFAULT_SESSION_ID_NAME;
        }
        return name;
    }

    protected Session createExposedSession(Session session, SessionContext context) {
        if (!WebUtils.isWeb(context)) {
            return super.createExposedSession(session, context);
        }
        ServletRequest request = WebUtils.getRequest(context);
        ServletResponse response = WebUtils.getResponse(context);
        SessionKey key = new WebSessionKey(session.getId(), request, response);
        return new DelegatingSession(this, key);
    }

    protected Session createExposedSession(Session session, SessionKey key) {
        if (!WebUtils.isWeb(key)) {
            return super.createExposedSession(session, key);
        }

        ServletRequest request = WebUtils.getRequest(key);
        ServletResponse response = WebUtils.getResponse(key);
        SessionKey sessionKey = new WebSessionKey(session.getId(), request, response);
        return new DelegatingSession(this, sessionKey);
    }

    /**
     * Stores the Session's ID, usually as a Cookie, to associate with future requests.
     *
     * @param session the session that was just {@link #createSession created}.
     */
    @Override
    protected void onStart(Session session, SessionContext context) {
        super.onStart(session, context);

        if (!WebUtils.isHttp(context)) {
            LOGGER.debug("SessionContext argument is not HTTP compatible or does not have an HTTP request/response "
                    + "pair. No session ID cookie will be set.");
            return;

        }
        HttpServletRequest request = WebUtils.getHttpRequest(context);
        HttpServletResponse response = WebUtils.getHttpResponse(context);

        if (isSessionIdCookieEnabled()) {
            Serializable sessionId = session.getId();
            storeSessionId(sessionId, request, response);
        } else {
            LOGGER.debug("Session ID cookie is disabled.  No cookie has been set for new session with id {}", session.getId());
        }

        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
    }

    @Override
    public Serializable getSessionId(SessionKey key) {
        Serializable id = super.getSessionId(key);
        if (id == null && WebUtils.isWeb(key)) {
            ServletRequest request = WebUtils.getRequest(key);
            ServletResponse response = WebUtils.getResponse(key);
            id = getSessionId(request, response);
        }
        return id;
    }

    protected Serializable getSessionId(ServletRequest request, ServletResponse response) {
        return getReferencedSessionId(request, response);
    }

    @Override
    protected void onExpiration(Session s, ExpiredSessionException ese, SessionKey key) {
        super.onExpiration(s, ese, key);
        onInvalidation(key);
    }

    @Override
    protected void onInvalidation(Session session, InvalidSessionException ise, SessionKey key) {
        super.onInvalidation(session, ise, key);
        onInvalidation(key);
    }

    private void onInvalidation(SessionKey key) {
        ServletRequest request = WebUtils.getRequest(key);
        if (request != null) {
            request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
        }
        if (WebUtils.isHttp(key)) {
            LOGGER.debug("Referenced session was invalid.  Removing session ID cookie.");
            removeSessionIdCookie(WebUtils.getHttpRequest(key), WebUtils.getHttpResponse(key));
        } else {
            LOGGER.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response "
                    + "pair. Session ID cookie will not be removed due to invalidated session.");
        }
    }

    @Override
    protected void onStop(Session session, SessionKey key) {
        super.onStop(session, key);
        if (WebUtils.isHttp(key)) {
            HttpServletRequest request = WebUtils.getHttpRequest(key);
            HttpServletResponse response = WebUtils.getHttpResponse(key);
            LOGGER.debug("Session has been stopped (subject logout or explicit stop).  Removing session ID cookie.");
            removeSessionIdCookie(request, response);
        } else {
            LOGGER.debug("SessionKey argument is not HTTP compatible or does not have an HTTP request/response "
                    + "pair. Session ID cookie will not be removed due to stopped session.");
        }
    }

    /**
     * This is a native session manager implementation, so this method returns {@code false} always.
     *
     * @return {@code false} always
     * @since 1.2
     */
    public boolean isServletContainerSessions() {
        return false;
    }
}
