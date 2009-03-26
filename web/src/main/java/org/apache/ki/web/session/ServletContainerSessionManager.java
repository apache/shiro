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
package org.apache.ki.web.session;

import java.io.Serializable;
import java.net.InetAddress;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.ki.authz.AuthorizationException;
import org.apache.ki.authz.HostUnauthorizedException;
import org.apache.ki.session.InvalidSessionException;
import org.apache.ki.session.Session;
import org.apache.ki.session.mgt.AbstractSessionManager;
import org.apache.ki.web.WebUtils;


/**
 * SessionManager implementation providing Session implementations that are merely wrappers for the
 * Servlet container's HttpSession.
 * <p/>
 * Despite its name, this implementation <em>does not</em> itself manage Sessions since the Servlet container
 * provides the actual management support.  This class mainly exists to 'impersonate' a regular Ki
 * <tt>SessionManager</tt> so it can be pluggable into a normal Ki configuration in a pure web application.
 * <p/>
 * Note that because this implementation relies on the {@link HttpSession HttpSession}, it is only functional in a
 * servlet container.  I.e. it is <em>NOT</em> capable of supporting Sessions any clients other than
 * {@code HttpRequest/HttpResponse} based clients.
 *
 * <p>Therefore, if you need {@code Session} access from heterogenous client mediums (e.g. web pages,
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

    protected Session doGetSession(Serializable sessionId) throws InvalidSessionException {
        //Ignore session id since there is no way to acquire a session based on an id in a servlet container
        //(that is implementation agnostic)
        ServletRequest request = WebUtils.getRequiredServletRequest();
        ServletResponse response = WebUtils.getRequiredServletResponse();
        return getSession(request, response);
    }

    public Session getSession(ServletRequest request, ServletResponse response) throws AuthorizationException {
        Session session = null;
        HttpSession httpSession = ((HttpServletRequest) request).getSession(false);
        if (httpSession != null) {
            session = createSession(httpSession, WebUtils.getInetAddress(request));
        }
        return session;
    }

    protected Session createSession(InetAddress originatingHost) throws HostUnauthorizedException, IllegalArgumentException {
        ServletRequest request = WebUtils.getRequiredServletRequest();
        HttpSession httpSession = ((HttpServletRequest) request).getSession();

        //ensure that the httpSession timeout reflects what is configured:
        long timeoutMillis = getGlobalSessionTimeout();
        httpSession.setMaxInactiveInterval((int) (timeoutMillis / MILLIS_PER_SECOND));

        return createSession(httpSession, originatingHost);
    }

    protected Session createSession(HttpSession httpSession, InetAddress inet) {
        return new WebSession(httpSession, inet);
    }

}
