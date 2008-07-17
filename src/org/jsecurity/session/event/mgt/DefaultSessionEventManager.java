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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jsecurity.session.Session;
import org.jsecurity.session.event.SessionEvent;
import org.jsecurity.session.event.SessionEventListener;

import java.util.Collection;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultSessionEventManager implements SessionEventManager {

    protected transient final Log log = LogFactory.getLog(getClass());

    protected SessionEventSender sessionEventSender = new DefaultSessionEventSender();
    protected SessionEventFactory sessionEventFactory = new DefaultSessionEventFactory();

    public DefaultSessionEventManager() {
    }

    public SessionEventSender getSessionEventSender() {
        return sessionEventSender;
    }

    public void setSessionEventSender(SessionEventSender sessionEventSender) {
        this.sessionEventSender = sessionEventSender;
    }

    public SessionEventFactory getSessionEventFactory() {
        return sessionEventFactory;
    }

    public void setSessionEventFactory(SessionEventFactory sessionEventFactory) {
        this.sessionEventFactory = sessionEventFactory;
    }

    public void add(SessionEventListener listener) {
        this.sessionEventSender.add(listener);
    }

    public boolean remove(SessionEventListener listener) {
        return this.sessionEventSender.remove(listener);
    }

    public void setSessionEventListeners(Collection<SessionEventListener> listeners) {
        this.sessionEventSender.setSessionEventListeners(listeners);
    }

    public boolean isSendingEvents() {
        return this.sessionEventSender.isSendingEvents();
    }

    public void send(SessionEvent event) {
        this.sessionEventSender.send(event);
    }

    public SessionEvent createStartEvent(Session session) {
        return this.sessionEventFactory.createStartEvent(session);
    }

    public SessionEvent createStopEvent(Session session) {
        return this.sessionEventFactory.createStopEvent(session);
    }

    public SessionEvent createExpirationEvent(Session session) {
        return this.sessionEventFactory.createExpirationEvent(session);
    }

    public void sendStartEvent(Session session) {
        if (isSendingEvents()) {
            SessionEvent startEvent = createStartEvent(session);
            send(startEvent);
        }
    }

    public void sendStopEvent(Session session) {
        if (isSendingEvents()) {
            SessionEvent stopEvent = createStopEvent(session);
            send(stopEvent);
        }
    }

    public void sendExpirationEvent(Session session) {
        if (isSendingEvents()) {
            SessionEvent expiredEvent = createExpirationEvent(session);
            send(expiredEvent);
        }
    }
}
