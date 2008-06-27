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
package org.jsecurity.authc.event.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.authc.event.AuthenticationEvent;
import org.jsecurity.authc.event.AuthenticationEventListener;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Simple implementation that 'sends' an event by synchronously calling any registered
 * {@link org.jsecurity.authc.event.AuthenticationEventListener}s.
 *
 * @author Les Hazlewood
 * @see org.jsecurity.authc.event.AuthenticationEventListener#onEvent
 * @since 0.1
 */
public class DefaultAuthenticationEventSender implements AuthenticationEventSender {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected Collection<AuthenticationEventListener> listeners = null;

    public DefaultAuthenticationEventSender() {
    }

    public DefaultAuthenticationEventSender(Collection<AuthenticationEventListener> listeners) {
        setAuthenticationEventListeners(listeners);
    }

    public boolean isSendingEvents() {
        return this.listeners != null && !this.listeners.isEmpty();
    }

    /**
     * Sets the <tt>AuthenticationEventListener</tt> collection that will be called when an event is triggered.
     *
     * @param listeners the AuthenticationEventListener collection that will be called when an event is triggered.
     */
    public void setAuthenticationEventListeners(Collection<AuthenticationEventListener> listeners) {
        this.listeners = listeners;
    }

    public Collection<AuthenticationEventListener> getAuthenticationEventListeners() {
        return listeners;
    }

    protected Collection<AuthenticationEventListener> getListenersLazy() {
        Collection<AuthenticationEventListener> listeners = getAuthenticationEventListeners();
        if (listeners == null) {
            listeners = new ArrayList<AuthenticationEventListener>();
            setAuthenticationEventListeners(listeners);
        }
        return listeners;
    }

    public void add(AuthenticationEventListener listener) {
        getListenersLazy().add(listener);
    }

    public boolean remove(AuthenticationEventListener listener) {
        boolean removed = false;
        if (listener != null) {
            Collection<AuthenticationEventListener> listeners = getAuthenticationEventListeners();
            if (listeners != null) {
                removed = listeners.remove(listener);
            }
        }
        return removed;
    }

    /**
     * Sends the specified <tt>event</tt> to all registered {@link AuthenticationEventListener}s by
     * synchronously calling <tt>listener.onEvent(Event)</tt> for each listener configured in this sender's
     * internal listener list.
     */
    public void send(AuthenticationEvent event) {
        if (isSendingEvents()) {
            for (AuthenticationEventListener ael : listeners) {
                ael.onEvent(event);
            }
        } else {
            if (log.isWarnEnabled()) {
                String msg = "internal listeners collection is null.  No " +
                        "AuthenticationEventListeners will be notified of event [" +
                        event + "]";
                log.warn(msg);
            }
        }
    }

    /**
     * Adds the given <tt>AuthenticationEventListener</tt> to the internal collection of listeners that will be
     * synchronously called when an event is triggered.
     *
     * @param listener the listener to receive AuthenticationEvents
     */
    public void addListener(AuthenticationEventListener listener) {
        if (listener == null) {
            String msg = "Attempting to add a null authentication event listener";
            throw new IllegalArgumentException(msg);
        }
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }
}
