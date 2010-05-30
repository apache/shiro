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

/**
 * A simple factory class that instantiates concrete {@link Session Session} instances.  This is mainly a
 * mechanism to allow instances to be created at runtime if they need to be different the
 * defaults.  It is not used by end-users of the framework, but rather those configuring Shiro to work in an
 * application, and is typically injected into the {@link org.apache.shiro.mgt.SecurityManager SecurityManager} or a
 * {@link SessionManager}.
 *
 * @since 1.0
 */
public interface SessionFactory {

    /**
     * Creates a new {@code Session} instance based on the specified contextual initialization data.
     *
     * @param initData the initialization data to be used during {@link Session} creation.
     * @return a new {@code Session} instance.
     * @since 1.0
     */
    Session createSession(SessionContext initData);
}
