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


/**
 * Web-application capable <tt>SessionManager</tt> implementation.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultWebSessionManager extends DefaultSessionManager implements WebSessionManager {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSessionManager.class);

    private CookieAttribute<Serializable> sessionIdCookieAttribute = null;
    private RequestParamAttribute<Serializable> sessionIdRequestParamAttribute = null;

    public DefaultWebSessionManager() {
        this.sessionIdCookieAttribute = new CookieAttribute<Serializable>(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        this.sessionIdCookieAttribute.setCheckRequestParams(false);
        this.sessionIdRequestParamAttribute =
                new RequestParamAttribute<Serializable>(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
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

    protected void storeSessionId(Serializable currentId, ServletRequest request, ServletResponse response) {
        if (currentId == null) {
            String msg = "sessionId cannot be null when persisting for subsequent requests.";
            throw new IllegalArgumentException(msg);
        }
        getSessionIdCookieAttribute().storeValue(currentId, request, response);
    }

    private void markSessionIdValid(Serializable sessionId, ServletRequest request) {
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
    }

    private void markSessionIdInvalid(ServletRequest request) {
        request.removeAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID);
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
