/*
 * Copyright 2005-2008 Les Hazlewood
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web;

import org.jsecurity.mgt.DefaultSecurityManager;
import org.jsecurity.realm.Realm;
import org.jsecurity.session.InvalidSessionException;
import org.jsecurity.session.Session;
import org.jsecurity.session.mgt.SessionManager;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;
import org.jsecurity.web.session.ServletContainerSessionManager;
import org.jsecurity.web.session.WebSessionManager;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.net.InetAddress;
import java.util.Collection;

/**
 * SecurityManager implementation that should be used in web-based applications or any application that requires
 * HTTP connectivity (SOAP, http remoting, etc).
 * 
 * @author Les Hazlewood
 * @since 0.2
 */
public class WebSecurityManager extends DefaultSecurityManager {

    public static final String HTTP_SESSION_MODE = "http";
    public static final String JSECURITY_SESSION_MODE = "jsecurity";

    /** The key that is used to store subject principals in the session. */
    public static final String PRINCIPALS_SESSION_KEY = WebSecurityManager.class.getName() + "_PRINCIPALS_SESSION_KEY";

    /** The key that is used to store whether or not the user is authenticated in the session. */
    public static final String AUTHENTICATED_SESSION_KEY = WebSecurityManager.class.getName() + "_AUTHENTICATED_SESSION_KEY";

    private String sessionMode = HTTP_SESSION_MODE; //default

    public WebSecurityManager() {
        super();
    }

    public WebSecurityManager(Realm singleRealm) {
        super(singleRealm);
    }

    public WebSecurityManager(Collection<Realm> realms) {
        super(realms);
    }

    protected void afterSessionManagerSet() {
        WebRememberMeManager rmm = new WebRememberMeManager();
        setRememberMeManager(rmm);
    }

    public String getSessionMode() {
        return sessionMode;
    }

    public void setSessionMode(String sessionMode) {
        if ( sessionMode == null ||
             (!sessionMode.equals(HTTP_SESSION_MODE) && !sessionMode.equals(JSECURITY_SESSION_MODE ) ) ) {
            String msg = "Invalid sessionMode [" + sessionMode + "].  Allowed values are " +
                    "public static final String constants in the " + getClass().getName() + " class: '" 
                    + HTTP_SESSION_MODE + "' or '" + JSECURITY_SESSION_MODE + "', with '" +
                    HTTP_SESSION_MODE + "' being the default.";
            throw new IllegalArgumentException(msg );
        }
        this.sessionMode = sessionMode;
    }

    protected boolean isHttpSessionMode() {
        return this.sessionMode.equals(HTTP_SESSION_MODE);
    }

    protected SessionManager createSessionManager() {

        if (isHttpSessionMode()) {
            if ( log.isInfoEnabled() ) {
                log.info( HTTP_SESSION_MODE + " mode - enabling ServletContainerSessionManager (Http Sessions)" );
            }
            ServletContainerSessionManager scsm = new ServletContainerSessionManager();
            scsm.setSessionEventListeners(getSessionEventListeners());
            return scsm;
        } else {
            if ( log.isInfoEnabled() ) {
                log.info( JSECURITY_SESSION_MODE + " mode - enabling WebSessionManager (JSecurity heterogenous sessions)");
            }
            WebSessionManager wsm = new WebSessionManager();
            wsm.setCacheManager(getCacheManager());
            wsm.setSessionEventListeners(getSessionEventListeners());
            wsm.init();
            return wsm;
        }
    }

    protected Object getPrincipals(Session session) {
        Object principals = null;
        if (session != null) {
            principals = session.getAttribute(PRINCIPALS_SESSION_KEY);
        }
        return principals;
    }

    protected Object getPrincipals(Session existing, ServletRequest servletRequest, ServletResponse servletResponse) {
        Object principals = getPrincipals(existing);
        if (principals == null) {
            //check remember me:
            principals = getRememberedIdentity();
            if (principals != null && existing != null) {
                existing.setAttribute(PRINCIPALS_SESSION_KEY, principals);
            }
        }
        return principals;
    }

    protected boolean isAuthenticated(Session session) {
        Boolean value = null;
        if (session != null) {
            value = (Boolean) session.getAttribute(AUTHENTICATED_SESSION_KEY);
        }
        return value != null && value;
    }

    protected boolean isAuthenticated(ServletRequest servletRequest, ServletResponse servletResponse, Session existing) {
        return isAuthenticated(existing);
    }

    public Subject createSubject() {
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        return createSubject(request, response);
    }

    public Subject createSubject(ServletRequest request, ServletResponse response) {
        Session session = null; 
        try {
            session = getSession(null);
        } catch (InvalidSessionException ignored) {
            if ( log.isTraceEnabled() ) {
                log.trace( "No Session exists for the incoming request and is therefore not available to use to " +
                        "construct a Subject instance.  This is perfectly ok and a new Subject instance will be " +
                        "created.  This exception can be ignored - logging for traceability only.", ignored );
            }
        }
        return createSubject(session, request, response);
    }

    public Subject createSubject(Session existing, ServletRequest request, ServletResponse response) {
        Object principals = getPrincipals(existing, request, response);
        boolean authenticated = isAuthenticated(request, response, existing);
        return createSubject(request, response, existing, principals, authenticated);
    }

    protected Subject createSubject(ServletRequest request,
                                    ServletResponse response,
                                    Session existing,
                                    Object principals,
                                    boolean authenticated) {
        InetAddress inetAddress = SecurityWebSupport.getInetAddress(request);
        return createSubject(principals, existing, authenticated, inetAddress);
    }

    protected void bind(Subject subject) {
        super.bind(subject);
        ServletRequest request = ThreadContext.getServletRequest();
        ServletResponse response = ThreadContext.getServletResponse();
        bind(subject, request, response);
    }

    protected void bind(Subject subject, ServletRequest request, ServletResponse response) {
        Object principals = subject.getPrincipal();
        if ((principals instanceof Collection) && ((Collection) principals).isEmpty()) {
            principals = null;
        }
        if (principals != null) {
            Session session = subject.getSession();
            session.setAttribute(PRINCIPALS_SESSION_KEY, principals);
        } else {
            Session session = subject.getSession(false);
            if (session != null) {
                session.removeAttribute(PRINCIPALS_SESSION_KEY);
            }
        }

        if (subject.isAuthenticated()) {
            Session session = subject.getSession();
            session.setAttribute(AUTHENTICATED_SESSION_KEY, subject.isAuthenticated());
        } else {
            Session session = subject.getSession(false);
            if (session != null) {
                session.removeAttribute(AUTHENTICATED_SESSION_KEY);
            }
        }
    }
}
