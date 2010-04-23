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

    public DefaultWebSessionManager() {
        this.sessionIdCookie = new SimpleCookie(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        this.sessionIdCookie.setPath(Cookie.ROOT_PATH);
    }

    public Cookie getSessionIdCookie() {
        return sessionIdCookie;
    }

    public void setSessionIdCookie(Cookie sessionIdCookie) {
        this.sessionIdCookie = sessionIdCookie;
    }

    protected void storeSessionId(Serializable currentId, ServletRequest request, ServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        Cookie template = getSessionIdCookie();
        Cookie cookie = new SimpleCookie(template);
        cookie.setValue(currentId.toString());
        cookie.saveTo(WebUtils.toHttp(request), WebUtils.toHttp(response));
    }

    private void markSessionIdValid(Serializable sessionId, ServletRequest request) {
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
    }

    private void markSessionIdInvalid(ServletRequest request) {
        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
    }

    private void removeSessionIdCookie(ServletRequest request, ServletResponse response) {
        getSessionIdCookie().removeFrom(WebUtils.toHttp(request), WebUtils.toHttp(response));
    }

    protected Serializable getReferencedSessionId(ServletRequest request, ServletResponse response) {
        String id = getSessionIdCookie().readValue(WebUtils.toHttp(request), WebUtils.toHttp(response));
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                    ShiroHttpServletRequest.COOKIE_SESSION_ID_SOURCE);
        } else {
            id = request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
            if (id != null) {
                request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                        ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
            }
        }
        if (id != null) {
            request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
            //automatically mark it valid here.  If it is invalid, the
            //onUnknownSession method below will be invoked and we'll remove the attribute at that time.
            markSessionIdValid(id, request);
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
        Serializable sessionId = session.getId();
        storeSessionId(sessionId, request, response);
        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
    }

    public Serializable getSessionId(ServletRequest request, ServletResponse response) {
        return getReferencedSessionId(request, response);
    }

    @Override
    public void onUnknownSession(Serializable sessionId) {
        markSessionIdInvalid(WebUtils.getRequiredServletRequest());
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

    protected void removeSessionIdCookie() {
        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        removeSessionIdCookie(request, response);
    }
}
