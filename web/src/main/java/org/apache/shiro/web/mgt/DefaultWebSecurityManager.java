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
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SessionStorageEvaluator;
import org.apache.shiro.mgt.SubjectDAO;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.SubjectContext;
import org.apache.shiro.lang.util.LifecycleUtils;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.session.mgt.DefaultWebSessionContext;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.apache.shiro.web.session.mgt.ServletContainerSessionManager;
import org.apache.shiro.web.session.mgt.WebSessionKey;
import org.apache.shiro.web.session.mgt.WebSessionManager;
import org.apache.shiro.web.subject.WebSubject;
import org.apache.shiro.web.subject.WebSubjectContext;
import org.apache.shiro.web.subject.support.DefaultWebSubjectContext;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.Serializable;
import java.util.Collection;
import java.util.function.Supplier;


/**
 * Default {@link WebSecurityManager WebSecurityManager} implementation used in web-based applications or any
 * application that requires HTTP connectivity (SOAP, http remoting, etc.).
 *
 * @since 0.2
 */
public class DefaultWebSecurityManager extends DefaultSecurityManager implements WebSecurityManager {

    @SuppressWarnings("checkstyle:JavadocVariable")
    @Deprecated
    public static final String HTTP_SESSION_MODE = "http";
    @SuppressWarnings("checkstyle:JavadocVariable")
    @Deprecated
    public static final String NATIVE_SESSION_MODE = "native";

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultWebSecurityManager.class);

    /**
     * @deprecated as of 1.2.  This should NOT be used for anything other than determining if the sessionMode has changed.
     */
    @Deprecated
    private String sessionMode;

    public DefaultWebSecurityManager() {
        super();
        init(null);
    }

    public DefaultWebSecurityManager(Supplier<byte[]> keySupplier) {
        super();
        init(keySupplier);
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

    private void init(Supplier<byte[]> keySupplier) {
        DefaultWebSessionStorageEvaluator webEvaluator = new DefaultWebSessionStorageEvaluator();
        ((DefaultSubjectDAO) this.subjectDAO).setSessionStorageEvaluator(webEvaluator);
        this.sessionMode = HTTP_SESSION_MODE;
        setSubjectFactory(new DefaultWebSubjectFactory());
        setRememberMeManager(keySupplier == null ? new CookieRememberMeManager()
                : new CookieRememberMeManager(keySupplier));
        setSessionManager(new ServletContainerSessionManager());
        webEvaluator.setSessionManager(getSessionManager());
    }

    @Override
    //since 1.2.1 for fixing SHIRO-350
    public void setSubjectDAO(SubjectDAO subjectDAO) {
        super.setSubjectDAO(subjectDAO);
        applySessionManagerToSessionStorageEvaluatorIfPossible();
    }

    //since 1.2.1 for fixing SHIRO-350
    @Override
    protected void afterSessionManagerSet() {
        super.afterSessionManagerSet();
        applySessionManagerToSessionStorageEvaluatorIfPossible();
    }

    //since 1.2.1 for fixing SHIRO-350:
    private void applySessionManagerToSessionStorageEvaluatorIfPossible() {
        SubjectDAO subjectDAO = getSubjectDAO();
        if (subjectDAO instanceof DefaultSubjectDAO aO) {
            SessionStorageEvaluator evaluator = aO.getSessionStorageEvaluator();
            if (evaluator instanceof DefaultWebSessionStorageEvaluator storageEvaluator) {
                storageEvaluator.setSessionManager(getSessionManager());
            }
        }
    }

    @Override
    protected SubjectContext copy(SubjectContext subjectContext) {
        if (subjectContext instanceof WebSubjectContext context) {
            return new DefaultWebSubjectContext(context);
        }
        return super.copy(subjectContext);
    }

    @SuppressWarnings({"UnusedDeclaration"})
    @Deprecated
    public String getSessionMode() {
        return sessionMode;
    }

    /**
     * @param sessionMode
     * @deprecated since 1.2
     */
    @Deprecated
    public void setSessionMode(String sessionMode) {
        LOGGER.warn("The 'sessionMode' property has been deprecated.  Please configure an appropriate WebSessionManager "
                + "instance instead of using this property.  This property/method will be removed in a later version.");
        String mode = sessionMode;
        if (mode == null) {
            throw new IllegalArgumentException("sessionMode argument cannot be null.");
        }
        mode = sessionMode.toLowerCase();
        if (!HTTP_SESSION_MODE.equals(mode) && !NATIVE_SESSION_MODE.equals(mode)) {
            String msg = "Invalid sessionMode [" + sessionMode + "].  Allowed values are "
                    + "public static final String constants in the " + getClass().getName() + " class: '"
                    + HTTP_SESSION_MODE + "' or '" + NATIVE_SESSION_MODE + "', with '"
                    + HTTP_SESSION_MODE + "' being the default.";
            throw new IllegalArgumentException(msg);
        }
        boolean recreate = this.sessionMode == null || !this.sessionMode.equals(mode);
        this.sessionMode = mode;
        if (recreate) {
            LifecycleUtils.destroy(getSessionManager());
            SessionManager sessionManager = createSessionManager(mode);
            this.setInternalSessionManager(sessionManager);
        }
    }

    @Override
    public void setSessionManager(SessionManager sessionManager) {
        this.sessionMode = null;
        if (sessionManager != null && !(sessionManager instanceof WebSessionManager)) {
            if (LOGGER.isWarnEnabled()) {
                String msg = "The " + getClass().getName() + " implementation expects SessionManager instances "
                        + "that implement the " + WebSessionManager.class.getName() + " interface.  The "
                        + "configured instance is of type [" + sessionManager.getClass().getName() + "] which does not "
                        + "implement this interface..  This may cause unexpected behavior.";
                LOGGER.warn(msg);
            }
        }
        setInternalSessionManager(sessionManager);
    }

    /**
     * @param sessionManager
     * @since 1.2
     */
    private void setInternalSessionManager(SessionManager sessionManager) {
        super.setSessionManager(sessionManager);
    }

    /**
     * @since 1.0
     */
    public boolean isHttpSessionMode() {
        SessionManager sessionManager = getSessionManager();
        return sessionManager instanceof WebSessionManager wsm && wsm.isServletContainerSessions();
    }

    protected SessionManager createSessionManager(String sessionMode) {
        if (sessionMode == null || !sessionMode.equalsIgnoreCase(NATIVE_SESSION_MODE)) {
            LOGGER.info("{} mode - enabling ServletContainerSessionManager (HTTP-only Sessions)", HTTP_SESSION_MODE);
            return new ServletContainerSessionManager();
        } else {
            LOGGER.info("{} mode - enabling DefaultWebSessionManager (non-HTTP and HTTP Sessions)", NATIVE_SESSION_MODE);
            return new DefaultWebSessionManager();
        }
    }

    @Override
    protected SessionContext createSessionContext(SubjectContext subjectContext) {
        SessionContext sessionContext = super.createSessionContext(subjectContext);
        if (subjectContext instanceof WebSubjectContext wsc) {
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
        if (subject instanceof WebSubject webSubject) {
            ServletRequest request = webSubject.getServletRequest();
            if (request != null) {
                request.setAttribute(ShiroHttpServletRequest.IDENTITY_REMOVED_KEY, Boolean.TRUE);
            }
        }
    }
}
