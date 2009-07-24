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
package org.apache.shiro.session;

/**
 * Interface to be implemented by components that wish to be notified of events that occur during a
 * {@link Session Session}'s lifecycle.
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface SessionListener {

    /**
     * Notification callback that occurs when the corresponding Session has started.
     *
     * @param session the session that has started.
     */
    void onStart(Session session);

    /**
     * Notification callback that occurs when the corresponding Session has stopped.
     *
     * @param session the session that has stopped.
     */
    void onStop(Session session);

    /**
     * Notification callback that occurs when the corresponding Session has expired.
     *
     * @param session the session that has expired.
     */
    void onExpiration(Session session);
}
