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

import java.util.Collection;

/**
 * A {@code SessionListenerRegistrar} is a component that is capable of registering interested
 * {@link SessionListener SessionListener}s that wish to be notified during {@link Session Session} lifecycle events.
 * <p/>
 * This interface only specifies that registered listeners will be notified during a {@code Session}'s
 * lifecycle.  How that notification occurs is implementation specific (e.g. synchronous iteration over a collection of
 * listeners, or asynchronous JMS, etc.).
 *
 * @author Les Hazlewood
 * @since 0.9
 */
public interface SessionListenerRegistrar {

    /**
     * Sets the {@code SessionListener}(s) that wish to be notified during {@code Session} lifecycle events.
     *
     * @param listeners one or more {@code SessionListener}s that should be notified during {@code Session} lifecycle events.
     */
    void setSessionListeners(Collection<SessionListener> listeners);

    /**
     * Registers a single {@code listener} that wishes to be notified during {@code Session} lifecycle events.
     *
     * @param listener the single {@code listener} that wishes to be notified during {@code Session} lifecycle events.
     */
    void add(SessionListener listener);

    /**
     * Removes a single {@code listener} that no longer wishes to be notified during {@code Session} lifecycle events.
     *
     * @param listener the single {@code listener} that no longer wishes to be notified during {@code Session} lifecycle
     *                 events.
     * @return {@code true} if the listener was removed (i.e. it was previously registered), or {@code false}
     *         if the listener was not removed (i.e. it wasn't registered yet, effectively a no-op).
     */
    boolean remove(SessionListener listener);
}
