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

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.InvalidSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractSessionManager;
import org.apache.shiro.session.mgt.SessionContext;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;


/**
 * SessionManager implementation providing Session implementations that are merely wrappers for the
 * Servlet container's HttpSession.
 * <p/>
 * Despite its name, this implementation <em>does not</em> itself manage Sessions since the Servlet container
 * provides the actual management support.  This class mainly exists to 'impersonate' a regular Shiro
 * <tt>SessionManager</tt> so it can be pluggable into a normal Shiro configuration in a pure web application.
 * <p/>
 * Note that because this implementation relies on the {@link HttpSession HttpSession}, it is only functional in a
 * servlet container.  I.e. it is <em>NOT</em> capable of supporting Sessions any clients other than
 * {@code HttpRequest/HttpResponse} based clients.
 * <p/>
 * Therefore, if you need {@code Session} access from heterogenous client mediums (e.g. web pages,
 * Flash applets, Java Web Start applications, etc.), use the {@link DefaultWebSessionManager DefaultWebSessionManager}
 * instead.  The {@code DefaultWebSessionManager} supports both traditional web-based access as well as non web-based
 * clients.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public class ServletContainerSessionManager extends AbstractSessionManager implements WebSessionManager {

    //TODO - complete JavaDoc

    //TODO - read session timeout value from web.xml

    public ServletContainerSessionManager() {
    }

    @Override
    public Session start(SessionContext initData) throws AuthorizationException {
        return createSession(initData);
    }

    /**
     * This method exists only to satisfy the parent's abstract method signature.  It should never be called since
     * there is no way to obtain a Session instance from a Servlet Container by id (in a system independent
     * manner).
     * <p/>
     * This method will always throw an exception if called since the
     * {@link #getSession(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method should be used in all
     * cases instead.
     *
     * @param sessionId
     * @return
     * @throws InvalidSessionException
     */
    protected Session doGetSession(Serializable sessionId) throws InvalidSessionException {
        //Ignore session id since there is no way to acquire a session based on an id in a servlet container
        //(that is implementation agnostic)
        String msg = "Cannot retrieve sessions by ID when Sessions are managed by the Servlet Container.  This " +
                "feature is available for Shiro 'native' session SessionManager implementations only.";
        throw new IllegalStateException(msg);
        /*ServletRequest request = WebUtils.getServletRequest();
        ServletResponse response = WebUtils.getServletResponse();
        if (request == null) {
            String msg = "Thread-bound ServletRequest cannot be null in ServletContainer-managed Session environments.";
            throw new IllegalStateException(msg);
        }
        return getSession(request, response);*/
    }

    /**
     * @since 1.0
     */
    public Session getSession(ServletRequest request, ServletResponse response) {
        Session session = null;
        HttpSession httpSession = ((HttpServletRequest) request).getSession(false);
        if (httpSession != null) {
            session = createSession(httpSession, request.getRemoteHost());
        }
        return session;
    }

    /**
     * @since 1.0
     */
    public Serializable getSessionId(ServletRequest request, ServletResponse response) {
        HttpSession httpSession = ((HttpServletRequest) request).getSession(false);
        return httpSession != null ? httpSession.getId() : null;
    }

    /**
     * @since 1.0
     */
    protected Session createSession(SessionContext sessionContext) throws AuthorizationException {
        if (!(sessionContext instanceof WebSessionContext)) {
            String msg = "SessionContext must be a " + WebSessionContext.class.getName() + " instance.";
            throw new IllegalArgumentException(msg);
        }

        WebSessionContext wsc = (WebSessionContext) sessionContext;

        ServletRequest request = wsc.getServletRequest();
        if (request == null) {
            String msg = "WebSessionContext must contain a ServletRequest.";
            throw new IllegalStateException(msg);
        }
        ServletResponse response = wsc.getServletResponse();
        if (response == null) {
            String msg = "WebSessionContext must contain a ServletResponse.";
            throw new IllegalStateException(msg);
        }

        HttpSession httpSession = ((HttpServletRequest) request).getSession();

        //ensure that the httpSession timeout reflects what is configured:
        long timeoutMillis = getGlobalSessionTimeout();
        httpSession.setMaxInactiveInterval((int) (timeoutMillis / MILLIS_PER_SECOND));

        String originatingHost = wsc.getHost();
        if (originatingHost == null) {
            originatingHost = request.getRemoteHost();
        }
        return createSession(httpSession, originatingHost);
    }

    protected Session createSession(HttpSession httpSession, String host) {
        return new HttpServletSession(httpSession, host);
    }

}
