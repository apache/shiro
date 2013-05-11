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
 * {@link Session Session}'s life cycle.
 *
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
     * Notification callback that occurs when the corresponding Session has stopped, either programmatically via
     * {@link Session#stop} or automatically upon a subject logging out.
     *
     * @param session the session that has stopped.
     */
    void onStop(Session session);

    /**
     * Notification callback that occurs when the corresponding Session has expired.
     * <p/>
     * <b>Note</b>: this method is almost never called at the exact instant that the {@code Session} expires.  Almost all
     * session management systems, including Shiro's implementations, lazily validate sessions - either when they
     * are accessed or during a regular validation interval.  It would be too resource intensive to monitor every
     * single session instance to know the exact instant it expires.
     * <p/>
     * If you need to perform time-based logic when a session expires, it is best to write it based on the
     * session's {@link org.apache.shiro.session.Session#getLastAccessTime() lastAccessTime} and <em>not</em> the time
     * when this method is called.
     *
     * @param session the session that has expired.
     */
    void onExpiration(Session session);
}
