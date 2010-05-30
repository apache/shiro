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
package org.apache.shiro.web.mgt;

import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.util.LifecycleUtils;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.DefaultWebSessionContext;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionKey;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;
import java.util.Collection;


/**
 * Default {@link WebSecurityManager WebSecurityManager} implementation used in web-based applications or any
 * application that requires HTTP connectivity (SOAP, http remoting, etc).
 *
 * @since 0.2
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager implements WebSecurityManager {

    //TODO - complete JavaDoc

    private static final Logger log = LoggerFactory.getLogger(DefaultWebSecurityManager.class);

    public static final String HTTP_SESSION_MODE = "http";
    public static final String NATIVE_SESSION_MODE = "native";

    private String sessionMode;

    public DefaultWebSecurityManager() {
        super();
        this.sessionMode = HTTP_SESSION_MODE;
        setSubjectFactory(new DefaultWebSubjectFactory());
        setRememberMeManager(new CookieRememberMeManager());
        setSessionManager(new ServletContainerSessionManager());
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public DefaultWebSecurityManager(Realm singleRealm) {
        this();
        setRealm(singleRealm);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    public DefaultWebSecurityManager(Collection<Realm> realms) {
        this();
        setRealms(realms);
    }

    @Override
    protected SubjectContext createSubjectContext() {
        return new DefaultWebSubjectContext();
    }

    @Override
    protected SubjectContext copy(SubjectContext subjectContext) {
        if (subjectContext instanceof WebSubjectContext) {
            return new DefaultWebSubjectContext((WebSubjectContext) subjectContext);
        }
        return super.copy(subjectContext);
    }

    @SuppressWarnings({"UnusedDeclaration"})
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
            SessionManager sessionManager = createSessionManager(mode);
            setSessionManager(sessionManager);
        }
    }

    /**
     * @since 1.0
     */
    public boolean isHttpSessionMode() {
        return this.sessionMode == null || this.sessionMode.equals(HTTP_SESSION_MODE);
    }

    protected SessionManager createSessionManager(String sessionMode) {
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
    protected SessionContext createSessionContext(SubjectContext subjectContext) {
        SessionContext sessionContext = super.createSessionContext(subjectContext);
        if (subjectContext instanceof WebSubjectContext) {
            WebSubjectContext wsc = (WebSubjectContext) subjectContext;
            ServletRequest request = wsc.resolveServletRequest();
            ServletResponse response = wsc.resolveServletResponse();
            DefaultWebSessionContext webSessionContext = new DefaultWebSessionContext(sessionContext);
            if (request != null) {
                webSessionContext.setServletRequest(request);
            }
            if (response != null) {
                webSessionContext.setServletResponse(response);
            }

            sessionContext = webSessionContext;
        }
        return sessionContext;
    }

    @Override
    protected SessionKey getSessionKey(SubjectContext context) {
        if (WebUtils.isWeb(context)) {
            Serializable sessionId = context.getSessionId();
            ServletRequest request = WebUtils.getRequest(context);
            ServletResponse response = WebUtils.getResponse(context);
            return new WebSessionKey(sessionId, request, response);
        } else {
            return super.getSessionKey(context);

        }
    }

    @Override
    protected void beforeLogout(Subject subject) {
        super.beforeLogout(subject);
        removeRequestIdentity(subject);
    }

    protected void removeRequestIdentity(Subject subject) {
        if (subject instanceof WebSubject) {
            WebSubject webSubject = (WebSubject) subject;
            ServletRequest request = webSubject.getServletRequest();
            if (request != null) {
                request.setAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY, Boolean.TRUE);
            }
        }
    }
}
