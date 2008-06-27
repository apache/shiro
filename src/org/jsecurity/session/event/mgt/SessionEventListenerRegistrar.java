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
package org.jsecurity.session.event.mgt;

import org.jsecurity.session.event.SessionEventListener;

import java.util.Collection;

/**
 * A <tt>SessionEventListenerRegistrar</tt> is responsible for registering and deregistering
 * {@link org.jsecurity.session.event.SessionEventListener}s so they may be notified when a {@link org.jsecurity.session.event.SessionEvent SessionEvent} occurs.
 *
 * @author Les Hazlewood
 * @see DefaultSessionEventSender
 * @since 0.9
 */
public interface SessionEventListenerRegistrar {
    void setSessionEventListeners(Collection<SessionEventListener> listeners);

    void add(SessionEventListener listener);

    boolean remove(SessionEventListener listener);
}
