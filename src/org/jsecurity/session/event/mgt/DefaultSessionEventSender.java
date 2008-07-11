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

import org.jsecurity.session.event.SessionEvent;
import org.jsecurity.session.event.SessionEventListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Simple implementation that synchronously calls any
 * {@link SessionEventListenerRegistrar registered} {@link org.jsecurity.session.event.SessionEventListener listener}s
 * when a <tt>SessionEvent</tt> occurs.
 *
 * @author Les Hazlewood
 * @see #setSessionEventListeners
 * @since 0.9
 */
public class DefaultSessionEventSender implements SessionEventSender {

    protected transient final Logger log = LoggerFactory.getLogger(getClass());

    protected Collection<SessionEventListener> listeners = null;

    public DefaultSessionEventSender() {
    }

    public DefaultSessionEventSender(Collection<SessionEventListener> listeners) {
        this.listeners = listeners;
    }

    public void setSessionEventListeners(Collection<SessionEventListener> listeners) {
        this.listeners = listeners;
    }

    public Collection<SessionEventListener> getSessionEventListeners() {
        return this.listeners;
    }

    public boolean isSendingEvents() {
        return this.listeners != null && !this.listeners.isEmpty();
    }

    protected Collection<SessionEventListener> getListenersLazy() {
        Collection<SessionEventListener> listeners = getSessionEventListeners();
        if (listeners == null) {
            listeners = new ArrayList<SessionEventListener>();
            setSessionEventListeners(listeners);
        }
        return listeners;
    }

    public void add(SessionEventListener listener) {
        if (listener == null) {
            String msg = "Attempting to add a null session event listener";
            throw new IllegalArgumentException(msg);
        }
        Collection<SessionEventListener> listeners = getListenersLazy();
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public boolean remove(SessionEventListener listener) {
        boolean removed = false;
        if (listener != null) {
            Collection<SessionEventListener> listeners = getSessionEventListeners();
            if (listeners != null) {
                removed = listeners.remove(listener);
            }
        }
        return removed;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link SessionEventListener}s.
     */
    public void send(SessionEvent event) {
        Collection<SessionEventListener> listeners = getSessionEventListeners();
        if (listeners != null && !listeners.isEmpty()) {
            for (SessionEventListener sel : listeners) {
                sel.onEvent(event);
            }
        }
    }
}
