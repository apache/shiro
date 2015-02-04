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

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.SessionContext;
import org.apache.shiro.session.mgt.SessionKey;
import org.apache.shiro.web.session.HttpServletSession;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;


/**
 * SessionManager implementation providing {@link Session} implementations that are merely wrappers for the
 * Servlet container's {@link HttpSession}.
 * <p/>
 * Despite its name, this implementation <em>does not</em> itself manage Sessions since the Servlet container
 * provides the actual management support.  This class mainly exists to 'impersonate' a regular Shiro
 * {@code SessionManager} so it can be pluggable into a normal Shiro configuration in a pure web application.
 * <p/>
 * Note that because this implementation relies on the {@link HttpSession HttpSession}, it is only functional in a
 * servlet container - it is not capable of supporting Sessions for any clients other than those using the HTTP
 * protocol.
 * <p/>
 * Therefore, if you need {@code Session} support for heterogeneous clients (e.g. web browsers,
 * RMI clients, etc), use the {@link DefaultWebSessionManager DefaultWebSessionManager}
 * instead.  The {@code DefaultWebSessionManager} supports both traditional web-based access as well as non web-based
 * clients.
 *
 * @since 0.9
 * @see DefaultWebSessionManager
 */
public class ServletContainerSessionManager implements WebSessionManager {

    //TODO - complete JavaDoc

    //TODO - read session timeout value from web.xml

    public ServletContainerSessionManager() {
    }

    public Session start(SessionContext context) throws AuthorizationException {
        return createSession(context);
    }

    public Session getSession(SessionKey key) throws SessionException {
        if (!WebUtils.isHttp(key)) {
            String msg = "SessionKey must be an HTTP compatible implementation.";
            throw new IllegalArgumentException(msg);
        }

        HttpServletRequest request = WebUtils.getHttpRequest(key);

        Session session = null;

        HttpSession httpSession = request.getSession(false);
        if (httpSession != null) {
            session = createSession(httpSession, request.getRemoteHost());
        }

        return session;
    }

    private String getHost(SessionContext context) {
        String host = context.getHost();
        if (host == null) {
            ServletRequest request = WebUtils.getRequest(context);
            if (request != null) {
                host = request.getRemoteHost();
            }
        }
        return host;

    }

    /**
     * @since 1.0
     */
    protected Session createSession(SessionContext sessionContext) throws AuthorizationException {
        if (!WebUtils.isHttp(sessionContext)) {
            String msg = "SessionContext must be an HTTP compatible implementation.";
            throw new IllegalArgumentException(msg);
        }

        HttpServletRequest request = WebUtils.getHttpRequest(sessionContext);

        HttpSession httpSession = request.getSession();

        //SHIRO-240: DO NOT use the 'globalSessionTimeout' value here on the acquired session.
        //see: https://issues.apache.org/jira/browse/SHIRO-240

        String host = getHost(sessionContext);

        return createSession(httpSession, host);
    }

    protected Session createSession(HttpSession httpSession, String host) {
        return new HttpServletSession(httpSession, host);
    }

    /**
     * This implementation always delegates to the servlet container for sessions, so this method returns
     * {@code true} always.
     *
     * @return {@code true} always
     * @since 1.2
     */
	public boolean isServletContainerSessions() {
		return true;
	}
}
