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
package org.apache.shiro.session.mgt.eis;

import org.apache.shiro.session.Session;

import java.io.Serializable;
import java.util.UUID;

/**
 * {@link SessionIdGenerator} that generates String values of JDK {@link java.util.UUID}'s as the session IDs.
 *
 * @since 1.0
 */
public class JavaUuidSessionIdGenerator implements SessionIdGenerator {

    /**
     * Ignores the method argument and simply returns
     * {@code UUID}.{@link java.util.UUID#randomUUID() randomUUID()}.{@code toString()}.
     *
     * @param session the {@link Session} instance to which the ID will be applied.
     * @return the String value of the JDK's next {@link UUID#randomUUID() randomUUID()}.
     */
    public Serializable generateId(Session session) {
        return UUID.randomUUID().toString();
    }
}
