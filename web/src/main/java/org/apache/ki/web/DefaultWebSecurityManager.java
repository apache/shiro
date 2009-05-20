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
package org.apache.ki.web;

import org.apache.ki.mgt.DefaultSecurityManager;
import org.apache.ki.realm.Realm;
import org.apache.ki.session.mgt.SessionManager;
import org.apache.ki.subject.PrincipalCollection;
import org.apache.ki.util.LifecycleUtils;
import org.apache.ki.web.servlet.KiHttpServletRequest;
import org.apache.ki.web.session.DefaultWebSessionManager;
import org.apache.ki.web.session.ServletContainerSessionManager;
import org.apache.ki.web.session.WebSessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import java.util.Collection;


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
    public static final String KI_SESSION_MODE = "ki";

    /** The key that is used to store subject principals in the session. */
    public static final String PRINCIPALS_SESSION_KEY = DefaultWebSecurityManager.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /** The key that is used to store whether or not the user is authenticated in the session. */
    public static final String AUTHENTICATED_SESSION_KEY = DefaultWebSecurityManager.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    private String sessionMode = HTTP_SESSION_MODE; //default

    public DefaultWebSecurityManager() {
        super();
        setRememberMeManager(new WebRememberMeManager());
        WebSessionManager sm = new ServletContainerSessionManager();
        setSessionManager(sm);
    }

    public DefaultWebSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    public DefaultWebSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    @Override
    protected void afterSessionManagerSet() {
        super.afterSessionManagerSet();
        WebSessionManager sessionManager = (WebSessionManager) getSessionManager();
        setSubjectFactory(new WebSubjectFactory(this, sessionManager));
    }

    /**
     * Sets the path used to store the remember me cookie.  This determines which paths
     * are able to view the remember me cookie.
     *
     * @param rememberMeCookiePath the path to use for the remember me cookie.
     */
    public void setRememberMeCookiePath(String rememberMeCookiePath) {
        ((WebRememberMeManager) getRememberMeManager()).setCookiePath(rememberMeCookiePath);
    }

    /**
     * Sets the maximum age allowed for the remember me cookie.  This basically sets how long
     * a user will be remembered by the "remember me" feature.  Used when calling
     * {@link javax.servlet.http.Cookie#setMaxAge(int) maxAge}.  Please see that JavaDoc for the semantics on the
     * repercussions of negative, zero, and positive values for the maxAge.
     *
     * @param rememberMeMaxAge the maximum age for the remember me cookie.
     */
    public void setRememberMeCookieMaxAge(Integer rememberMeMaxAge) {
        ((WebRememberMeManager) getRememberMeManager()).setCookieMaxAge(rememberMeMaxAge);
    }

    private DefaultWebSessionManager getSessionManagerForCookieAttributes() {
        SessionManager sessionManager = getSessionManager();
        if (!(sessionManager instanceof DefaultWebSessionManager)) {
            String msg = "The convenience passthrough methods for setting session id cookie attributes " +
                    "are only available when the underlying SessionManager implementation is " +
                    DefaultWebSessionManager.class.getName() + ", which is enabled by default when the " +
                    "sessionMode is 'ki'.";
            throw new IllegalStateException(msg);
        }
        return (DefaultWebSessionManager) sessionManager;
    }

    public void setSessionIdCookieName(String name) {
        getSessionManagerForCookieAttributes().setSessionIdCookieName(name);
    }

    public void setSessionIdCookiePath(String path) {
        getSessionManagerForCookieAttributes().setSessionIdCookiePath(path);
    }

    public void setSessionIdCookieMaxAge(int maxAge) {
        getSessionManagerForCookieAttributes().setSessionIdCookieMaxAge(maxAge);
    }

    public void setSessionIdCookieSecure(boolean secure) {
        getSessionManagerForCookieAttributes().setSessionIdCookieSecure(secure);
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
        if (!HTTP_SESSION_MODE.equals(mode) && !KI_SESSION_MODE.equals(mode)) {
            String msg = "Invalid sessionMode [" + sessionMode + "].  Allowed values are " +
                    "public static final String constants in the " + getClass().getName() + " class: '"
                    + HTTP_SESSION_MODE + "' or '" + KI_SESSION_MODE + "', with '" +
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
                log.info(KI_SESSION_MODE + " mode - enabling DefaultWebSessionManager (HTTP + heterogeneous-client sessions)");
            }
            return new DefaultWebSessionManager();
        }
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
            request.setAttribute(KiHttpServletRequest.IDENTITY_REMOVED_KEY, Boolean.TRUE);
        }
    }
}
