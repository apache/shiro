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
package org.apache.ki.session.mgt;

import org.apache.ki.session.Session;

import java.net.InetAddress;

/**
 * A simple factory class that instantiates concrete {@link Session Session} instances.  This is mainly an
 * SPI mechanism to allow different concrete instances to be created at runtime if they need to be different the
 * defaults.  It is typically not used by end-users of the framework.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public interface SessionFactory {

    /**
     * Creates a new {@code Session} for the party with the given {@code originatinHost}.  The host argument may be
     * {@code null} if unknown to the system.
     *
     * @param originatingHost the originating host InetAddress of the external party
     *                        (user, 3rd party product, etc) that is attempting to initiate the session, or
     *                        {@code null} if not known.
     * @return an new {@code Session} instance.
     */
    Session createSession(InetAddress originatingHost);
}
