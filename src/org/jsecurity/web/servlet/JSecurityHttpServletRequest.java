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
package org.jsecurity.web.servlet;

import org.jsecurity.SecurityUtils;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpSession;
import java.security.Principal;

/**
 * TODO class JavaDoc
 *
 * @author Les Hazlewood
 * @since 0.2
 */
@SuppressWarnings({"deprecated", "deprecation"})
public class JSecurityHttpServletRequest extends HttpServletRequestWrapper {

    //The following 7 constants support the JSecurity's implementation of the Servlet Specification
    public static final String COOKIE_SESSION_ID_SOURCE = "cookie";
    public static final String URL_SESSION_ID_SOURCE = "url";
    public static final String REFERENCED_SESSION_ID = JSecurityHttpServletRequest.class.getName() + "_REQUESTED_SESSION_ID";
    public static final String REFERENCED_SESSION_ID_IS_VALID = JSecurityHttpServletRequest.class.getName() + "_REQUESTED_SESSION_ID_VALID";
    public static final String REFERENCED_SESSION_IS_NEW = JSecurityHttpServletRequest.class.getName() + "_REFERENCED_SESSION_IS_NEW";
    public static final String REFERENCED_SESSION_ID_SOURCE = JSecurityHttpServletRequest.class.getName() + "REFERENCED_SESSION_ID_SOURCE";
    public static final String SESSION_ID_NAME = JSecurityHttpSession.DEFAULT_SESSION_ID_NAME;
    /**
     * Key that may be used to alert that the request's  referenced JSecurity Session has expired prior to
     * request processing.
     */
    public static final String EXPIRED_SESSION_KEY = JSecurityHttpServletRequest.class.getName() + "_EXPIRED_SESSION_KEY";

    protected ServletContext servletContext = null;

    protected HttpSession session = null;
    protected boolean httpSessions = true;

    public JSecurityHttpServletRequest(HttpServletRequest wrapped, ServletContext servletContext,
                                       boolean httpSessions) {
        super(wrapped);
        this.servletContext = servletContext;
        this.httpSessions = httpSessions;
    }

    public boolean isHttpSessions() {
        return httpSessions;
    }

    public String getRemoteUser() {
        String remoteUser;
        Object scPrincipal = getSubjectPrincipal();
        if (scPrincipal != null) {
            if (scPrincipal instanceof String) {
                return (String) scPrincipal;
            } else if (scPrincipal instanceof Principal) {
                remoteUser = ((Principal) scPrincipal).getName();
            } else {
                remoteUser = scPrincipal.toString();
            }
        } else {
            remoteUser = super.getRemoteUser();
        }
        return remoteUser;
    }

    protected Subject getSubject() {
        return SecurityUtils.getSubject();
    }

    protected Object getSubjectPrincipal() {
        Object userPrincipal = null;
        Subject subject = getSubject();
        if (subject != null) {
            userPrincipal = subject.getPrincipal();
        }
        return userPrincipal;
    }

    public boolean isUserInRole(String s) {
        Subject subject = getSubject();
        boolean inRole = (subject != null && subject.hasRole(s));
        if (!inRole) {
            inRole = super.isUserInRole(s);
        }
        return inRole;
    }

    public Principal getUserPrincipal() {
        Principal userPrincipal;
        Object scPrincipal = getSubjectPrincipal();
        if (scPrincipal != null) {
            if (scPrincipal instanceof Principal) {
                userPrincipal = (Principal) scPrincipal;
            } else {
                userPrincipal = new ObjectPrincipal(scPrincipal);
            }
        } else {
            userPrincipal = super.getUserPrincipal();
        }
        return userPrincipal;
    }

    public String getRequestedSessionId() {
        String requestedSessionId = null;
        if (isHttpSessions()) {
            requestedSessionId = super.getRequestedSessionId();
        } else {
            Object sessionId = getAttribute(REFERENCED_SESSION_ID);
            if (sessionId != null) {
                requestedSessionId = sessionId.toString();
            }
        }

        return requestedSessionId;
    }

    public HttpSession getSession(boolean create) {

        HttpSession httpSession;

        if (isHttpSessions()) {
            httpSession = super.getSession(create);
        } else {
            if (this.session == null) {

                boolean existing = getSubject().getSession(false) != null;

                Session jsecSession = getSubject().getSession(create);
                if (jsecSession != null) {
                    this.session = new JSecurityHttpSession(jsecSession, this, this.servletContext);
                    if (!existing) {
                        setAttribute(REFERENCED_SESSION_IS_NEW, Boolean.TRUE);
                    }
                }
            }
            httpSession = this.session;
        }

        return httpSession;
    }


    public HttpSession getSession() {
        return getSession(true);
    }

    public boolean isRequestedSessionIdValid() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdValid();
        } else {
            Boolean value = (Boolean) getAttribute(REFERENCED_SESSION_ID_IS_VALID);
            return (value != null && value.equals(Boolean.TRUE));
        }
    }

    public boolean isRequestedSessionIdFromCookie() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdFromCookie();
        } else {
            String value = (String) getAttribute(REFERENCED_SESSION_ID_SOURCE);
            return value != null && value.equals(COOKIE_SESSION_ID_SOURCE);
        }
    }

    public boolean isRequestedSessionIdFromURL() {
        if (isHttpSessions()) {
            return super.isRequestedSessionIdFromURL();
        } else {
            String value = (String) getAttribute(REFERENCED_SESSION_ID_SOURCE);
            return value != null && value.equals(URL_SESSION_ID_SOURCE);
        }
    }

    public boolean isRequestedSessionIdFromUrl() {
        return isRequestedSessionIdFromURL();
    }

    private class ObjectPrincipal implements java.security.Principal {
        private Object object = null;

        public ObjectPrincipal(Object object) {
            this.object = object;
        }

        public Object getObject() {
            return object;
        }

        public String getName() {
            return getObject().toString();
        }

        public int hashCode() {
            return object.hashCode();
        }

        public boolean equals(Object o) {
            if (o instanceof ObjectPrincipal) {
                ObjectPrincipal op = (ObjectPrincipal) o;
                return getObject().equals(op.getObject());
            }
            return false;
        }

        public String toString() {
            return object.toString();
        }
    }
}
