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

import org.apache.shiro.session.Session;

import java.net.InetAddress;
import java.util.Map;

/**
 * A simple factory class that instantiates concrete {@link Session Session} instances.  This is mainly a
 * mechanism to allow instances to be created at runtime if they need to be different the
 * defaults.  It is not used by end-users of the framework, but rather those configuring Shiro to work in an
 * application, and is typically injected into the {@link org.apache.shiro.mgt.SecurityManager SecurityManager} or a
 * {@link SessionManager}.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface SessionFactory {

    /**
     * The key under which an originating host's {@link InetAddress InetAddress} may be found in the
     * {@code initData} {@code Map} argument passed to the {@link #createSession(java.util.Map) createSession} method.
     */
    public static final String ORIGINATING_HOST_KEY = SessionFactory.class.getName() + ".originatingHost";

    /**
     * Creates a new {@code Session} instance based on the specified initialization data.  The originating host's
     * IP (InetAddress}, if available, should be accessible in the {@code Map} under the
     * {@link #ORIGINATING_HOST_KEY} key.  If not available, no value will be returned for that key ({@code null}).
     *
     * @param initData the initialization data to be used during {@link Session} instantiation.
     * @return a new {@code Session} instance.
     * @since 1.0
     */
    Session createSession(Map initData);
}
