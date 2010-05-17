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
import org.apache.shiro.session.SessionException;
import org.apache.shiro.session.mgt.SessionManager;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.Serializable;


/**
 * A {@code WebSessionManager} is a {@code SessionManager} that has the ability to obtain session ids based on a
 * {@link ServletRequest ServletRequest}/{@link ServletResponse ServletResponse} pair.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface WebSessionManager extends SessionManager {

    /**
     * Returns the session id associated with the specified request pair or {@code null} if there is no session
     * associated with the request.
     *
     * @param request  the incoming {@code ServletRequest}
     * @param response the outgoing {@code ServletResponse}
     * @return the current session id associated with the specified request pair, or {@code null} if there is no
     *         session associated with the request.
     * @since 1.0
     */
    Serializable getSessionId(ServletRequest request, ServletResponse response);

    /**
     * Returns the session associated with the specified request pair or {@code null} if there is no session
     * associated with the request.
     *
     * @param request  the incoming {@code ServletRequest}
     * @param response the outgoing {@code ServletResponse}
     * @return the current session associated with the specified request pair, or {@code null} if there is no
     *         session associated with the request.
     * @throws SessionException if there is a problem acquiring the Session associated with the request/response pair
     * @since 1.0
     */
    Session getSession(ServletRequest request, ServletResponse response) throws SessionException;
}
