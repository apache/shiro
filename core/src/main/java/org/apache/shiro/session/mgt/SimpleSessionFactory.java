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
 * {@code SessionFactory} implementation that generates {@link SimpleSession} instances.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class SimpleSessionFactory implements SessionFactory {

    /**
     * This default implementation merely returns
     * <pre>new {@link SimpleSession#SimpleSession(java.net.InetAddress) SimpleSession}({@link InetAddress originatingHost});</pre>
     *
     * @param originatingHost the originating host InetAddress of the external party
     *                        (user, 3rd party product, etc) that is attempting to initiate the session, or
     *                        {@code null} if not known.
     * @return a new session instance.
     */
    public Session createSession(InetAddress originatingHost) {
        return new SimpleSession(originatingHost);
    }

    public Session createSession(Map initData) {
        if (initData != null && initData.containsKey(SessionFactory.ORIGINATING_HOST_KEY)) {
            InetAddress host = (InetAddress) initData.get(SessionFactory.ORIGINATING_HOST_KEY);
            return new SimpleSession(host);
        }
        return new SimpleSession();
    }
}
