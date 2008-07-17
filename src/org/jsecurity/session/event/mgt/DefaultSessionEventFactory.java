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
import org.jsecurity.session.event.ExpiredSessionEvent;
import org.jsecurity.session.event.SessionEvent;
import org.jsecurity.session.event.StartedSessionEvent;
import org.jsecurity.session.event.StoppedSessionEvent;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultSessionEventFactory implements SessionEventFactory {

    protected transient final Log log = LogFactory.getLog(getClass());

    public DefaultSessionEventFactory() {
    }

    public SessionEvent createStartEvent(Session session) {
        return new StartedSessionEvent(this, session.getId());
    }

    public SessionEvent createStopEvent(Session session) {
        return new StoppedSessionEvent(this, session.getId());
    }

    public SessionEvent createExpirationEvent(Session session) {
        return new ExpiredSessionEvent(this, session.getId());
    }
}
