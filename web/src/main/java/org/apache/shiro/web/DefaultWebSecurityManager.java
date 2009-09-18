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
package org.apache.shiro.web;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.web.attr.CookieAttribute;
import org.apache.shiro.web.mgt.DefaultWebSubjectFactory;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.DefaultWebSessionManager;
import org.apache.shiro.web.session.ServletContainerSessionManager;
import org.apache.shiro.web.session.WebSessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;


/**
 * SecurityManager implementation that should be used in web-based applications or any application that requires
 * HTTP connectivity (SOAP, http remoting, etc).
 *
 * @author Les Hazlewood
 * @since 0.2
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSecurityManager.class);

    public static final String HTTP_SESSION_MODE = "http";
    public static final String NATIVE_SESSION_MODE = "native";

    private String sessionMode = HTTP_SESSION_MODE; //default

    public DefaultWebSecurityManager() {
        super();
        setSubjectFactory(new DefaultWebSubjectFactory(this));
        setRememberMeManager(new WebRememberMeManager());
        setSessionManager(new ServletContainerSessionManager());
    }

    public DefaultWebSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    public DefaultWebSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    //TODO - yuck - create an interface
    protected WebRememberMeManager getRememberMeManagerForCookieAttributes() {
        if (!(getRememberMeManager() instanceof WebRememberMeManager)) {
            String msg = "Currently the " + getClass().getName() + " implementation only allows setting " +
                    "rememberMe cookie attributes directly if the underlying RememberMeManager implementation " +
                    "is an " + WebRememberMeManager.class.getName() + " instance.";
            throw new IllegalStateException(msg);
        }
        return (WebRememberMeManager) getRememberMeManager();
    }

    protected CookieAttribute<String> getRememberMeCookieAttribute() {
        return (CookieAttribute<String>) getRememberMeManagerForCookieAttributes().getIdentityAttribute();
    }

    public void setRememberMeCookieAttribute(CookieAttribute<String> cookieAttribute) {
        getRememberMeManagerForCookieAttributes().setIdentityAttribute(cookieAttribute);
    }

    public void setRememberMeCookieName(String name) {
        getRememberMeCookieAttribute().setName(name);
    }

    public void setRememberMeCookieDomain(String domain) {
        getRememberMeCookieAttribute().setDomain(domain);
    }

    /**
     * Sets the path used to store the remember me cookie.  This determines which paths
     * are able to view the remember me cookie.
     *
     * @param rememberMeCookiePath the path to use for the remember me cookie.
     */
    public void setRememberMeCookiePath(String rememberMeCookiePath) {
        getRememberMeCookieAttribute().setPath(rememberMeCookiePath);
    }

    /**
     * Sets the maximum age allowed for the remember me cookie.  This basically sets how long
     * a user will be remembered by the "remember me" feature.  Used when calling
     * {@link javax.servlet.http.Cookie#setMaxAge(int) maxAge}.  Please see that JavaDoc for the semantics on the
     * repercussions of negative, zero, and positive values for the maxAge.                           i
     *
     * @param rememberMeMaxAge the maximum age for the remember me cookie.
     */
    public void setRememberMeCookieMaxAge(Integer rememberMeMaxAge) {
        getRememberMeCookieAttribute().setMaxAge(rememberMeMaxAge);
    }

    public void setRememberMeCookieVersion(int version) {
        getRememberMeCookieAttribute().setVersion(version);
    }

    public void setRememberMeCookieSecure(boolean secure) {
        getRememberMeCookieAttribute().setSecure(secure);
    }

    public void setRememberMeCookieComment(String comment) {
        getRememberMeCookieAttribute().setComment(comment);
    }

    private DefaultWebSessionManager getSessionManagerForCookieAttributes() {
        SessionManager sessionManager = getSessionManager();
        if (!(sessionManager instanceof DefaultWebSessionManager)) {
            String msg = "The convenience passthrough methods for setting session id cookie attributes " +
                    "are only available when the underlying SessionManager implementation is " +
                    DefaultWebSessionManager.class.getName() + ", which is enabled by default when the " +
                    "sessionMode is 'shiro'.";
            throw new IllegalStateException(msg);
        }
        return (DefaultWebSessionManager) sessionManager;
    }

    protected CookieAttribute<Serializable> getSessionIdCookieAttribute() {
        return getSessionManagerForCookieAttributes().getSessionIdCookieAttribute();
    }

    public void setSessionIdCookieAttribute(CookieAttribute<Serializable> cookieAttribute) {
        getSessionManagerForCookieAttributes().setSessionIdCookieAttribute(cookieAttribute);
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

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String sessionMode) {
        String mode = sessionMode;
        if (mode == null) {
            throw new IllegalArgumentException("sessionMode argument cannot be null.");
        }
        mode = sessionMode.toLowerCase();
        if (!HTTP_SESSION_MODE.equals(mode) && !NATIVE_SESSION_MODE.equals(mode)) {
            String msg = "Invalid sessionMode [" + sessionMode + "].  Allowed values are " +
                    "public static final String constants in the " + getClass().getName() + " class: '"
                    + HTTP_SESSION_MODE + "' or '" + NATIVE_SESSION_MODE + "', with '" +
                    HTTP_SESSION_MODE + "' being the default.";
            throw new IllegalArgumentException(msg);
        }
        boolean recreate = this.sessionMode == null || !this.sessionMode.equals(mode);
        this.sessionMode = mode;
        if (recreate) {
            LifecycleUtils.destroy(getSessionManager());
            WebSessionManager sessionManager = createSessionManager(mode);
            setSessionManager(sessionManager);
        }
    }

    public boolean isHttpSessionMode() {
        return this.sessionMode == null || this.sessionMode.equals(HTTP_SESSION_MODE);
    }

    protected WebSessionManager createSessionManager(String sessionMode) {
        if (sessionMode == null || sessionMode.equalsIgnoreCase(HTTP_SESSION_MODE)) {
            if (log.isInfoEnabled()) {
                log.info(HTTP_SESSION_MODE + " mode - enabling ServletContainerSessionManager (HTTP-only Sessions)");
            }
            return new ServletContainerSessionManager();
        } else {
            if (log.isInfoEnabled()) {
                log.info(NATIVE_SESSION_MODE + " mode - enabling DefaultWebSessionManager (HTTP + heterogeneous-client sessions)");
            }
            return new DefaultWebSessionManager();
        }
    }

    @Override
    protected Serializable getSessionId(Map subjectContext) {
        Serializable sessionId = super.getSessionId(subjectContext);
        if (sessionId == null) {
            ServletRequest request = (ServletRequest) subjectContext.get(SubjectFactory.SERVLET_REQUEST);
            ServletResponse response = (ServletResponse) subjectContext.get(SubjectFactory.SERVLET_RESPONSE);
            if (request != null && response != null) {
                sessionId = ((WebSessionManager) getSessionManager()).getSessionId(request, response);
            }
        }
        return sessionId;
    }

    @Override
    protected void beforeLogout(PrincipalCollection subjectIdentifier) {
        super.beforeLogout(subjectIdentifier);
        //also ensure a request attribute is set so the Subject is not reacquired later during the request:
        removeRequestIdentity();
    }

    protected void removeRequestIdentity() {
        ServletRequest request = WebUtils.getServletRequest();
        if (request != null) {
            request.setAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY, Boolean.TRUE);
        }
    }
}
