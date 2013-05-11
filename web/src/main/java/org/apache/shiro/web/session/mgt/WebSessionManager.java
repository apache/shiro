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

import org.apache.shiro.session.mgt.SessionManager;

/**
 * {@link SessionManager} specific to web-enabled applications.
 *
 * @since 1.2
 * @see ServletContainerSessionManager
 * @see DefaultWebSessionManager
 */
public interface WebSessionManager extends SessionManager {

    /**
     * Returns {@code true} if session management and storage is managed by the underlying Servlet container or
     * {@code false} if managed by Shiro directly (called 'native' sessions).
     * <p/>
     * If sessions are enabled, Shiro can make use of Sessions to retain security information from
     * request to request.  This method indicates whether Shiro would use the Servlet container sessions to fulfill its
     * needs, or if it would use its own native session management instead (which can support enterprise features
     * - like distributed caching - in a container-independent manner).
     *
     * @return {@code true} if session management and storage is managed by the underlying Servlet container or
     *         {@code false} if managed by Shiro directly (called 'native' sessions).
     */
    boolean isServletContainerSessions();
}
