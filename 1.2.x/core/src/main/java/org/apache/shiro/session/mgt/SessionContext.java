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
package org.apache.shiro.session.mgt;

import java.io.Serializable;
import java.util.Map;

/**
 * A {@code SessionContext} is a 'bucket' of data presented to a {@link SessionFactory SessionFactory} which interprets
 * this data to construct {@link org.apache.shiro.session.Session Session} instances.  It is essentially a Map of data
 * with a few additional type-safe methods for easy retrieval of objects commonly used to construct Subject instances.
 * <p/>
 * While this interface contains type-safe setters and getters for common data types, the map can contain anything
 * additional that might be needed by the {@code SessionFactory} implementation to construct {@code Session} instances.
 * <p/>
 * <b>USAGE</b>: Most Shiro end-users will never use a {@code SubjectContext} instance directly and instead will call
 * the {@code Subject.}{@link org.apache.shiro.subject.Subject#getSession() getSession()} or
 * {@code Subject.}{@link org.apache.shiro.subject.Subject#getSession(boolean) getSession(boolean)} methods (which
 * will usually use {@code SessionContext} instances to start a session with the application's
 * {@link SessionManager SessionManager}.
 *
 * @see org.apache.shiro.session.mgt.SessionManager#start SessionManager.start(SessionContext)
 * @see org.apache.shiro.session.mgt.SessionFactory SessionFactory
 * @since 1.0
 */
public interface SessionContext extends Map<String, Object> {

    /**
     * Sets the originating host name or IP address (as a String) from where the {@code Subject} is initiating the
     * {@code Session}.
     * <p/>
     * In web-based systems, this host can be inferred from the incoming request, e.g.
     * {@code javax.servlet.ServletRequest#getRemoteAddr()} or {@code javax.servlet.ServletRequest#getRemoteHost()}
     * methods, or in socket-based systems, it can be obtained via inspecting the socket
     * initiator's host IP.
     * <p/>
     * Most secure environments <em>should</em> specify a valid, non-{@code null} {@code host}, since knowing the
     * {@code host} allows for more flexibility when securing a system: by requiring an host, access control policies
     * can also ensure access is restricted to specific client <em>locations</em> in addition to {@code Subject}
     * principals, if so desired.
     * <p/>
     * <b>Caveat</b> - if clients to your system are on a
     * public network (as would be the case for a public web site), odds are high the clients can be
     * behind a NAT (Network Address Translation) router or HTTP proxy server.  If so, all clients
     * accessing your system behind that router or proxy will have the same originating host.
     * If your system is configured to allow only one session per host, then the next request from a
     * different NAT or proxy client will fail and access will be denied for that client.  Just be
     * aware that host-based security policies are best utilized in LAN or private WAN environments
     * when you can be ensure clients will not share IPs or be behind such NAT routers or
     * proxy servers.
     *
     * @param host the originating host name or IP address (as a String) from where the {@code Subject} is
     *             initiating the {@code Session}.
     * @since 1.0
     */
    void setHost(String host);

    /**
     * Returns the originating host name or IP address (as a String) from where the {@code Subject} is initiating the
     * {@code Session}.
     * <p/>
     * See the {@link #setHost(String) setHost(String)} JavaDoc for more about security policies based on the
     * {@code Session} host.
     *
     * @return the originating host name or IP address (as a String) from where the {@code Subject} is initiating the
     *         {@code Session}.
     * @see #setHost(String) setHost(String)
     */
    String getHost();

    Serializable getSessionId();

    void setSessionId(Serializable sessionId);

}
