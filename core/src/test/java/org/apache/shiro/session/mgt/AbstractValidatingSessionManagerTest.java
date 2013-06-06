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
package org.apache.shiro.session.mgt;

import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.SessionListener;
import org.apache.shiro.session.SessionListenerAdapter;
import org.apache.shiro.session.UnknownSessionException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

/**
 * Unit tests for the {@link org.apache.shiro.session.mgt.AbstractValidatingSessionManager} class.
 */
public class AbstractValidatingSessionManagerTest {

    /**
     * Tests that both SessionListeners are called and that invalid sessions are deleted by default.
     * Verifies <a href="https://issues.apache.org/jira/browse/SHIRO-199">SHIRO-199</a>.
     */
    @Test
    public void testValidateSessions() {

        final SimpleSession validSession = new SimpleSession();
        validSession.setId(1);
        final SimpleSession invalidSession = new SimpleSession();
        //set to a time in the past:
        Calendar cal = Calendar.getInstance();
        Long expiredTimeout = AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT + 1;
        cal.add(Calendar.MILLISECOND, -(expiredTimeout.intValue()) );
        Date past = cal.getTime();
        invalidSession.setStartTimestamp(past);
        invalidSession.setLastAccessTime(past);
        invalidSession.setId(2);

        final AtomicInteger expirationCount = new AtomicInteger();

        SessionListener sessionListener = new SessionListenerAdapter() {
            @Override
            public void onExpiration(Session session) {
                expirationCount.incrementAndGet();
            }
        };

        AbstractValidatingSessionManager sessionManager = new AbstractValidatingSessionManager() {
            @Override
            protected Session retrieveSession(SessionKey key) throws UnknownSessionException {
                throw new UnsupportedOperationException("Should not be called in this test.");
            }

            @Override
            protected Session doCreateSession(SessionContext initData) throws AuthorizationException {
                throw new UnsupportedOperationException("Should not be called in this test.");
            }

            @Override
            protected Collection<Session> getActiveSessions() {
                Collection<Session> sessions = new ArrayList<Session>(2);
                sessions.add(validSession);
                sessions.add(invalidSession);
                return sessions;
            }
        };

        sessionManager.setSessionListeners(Arrays.asList(sessionListener));
        sessionManager.validateSessions();
        
        assertEquals(1, expirationCount.intValue());
    }


    /**
     * Tests that no memory leak exists on invalid sessions: expired or stopped
     * Verifies <a href="https://issues.apache.org/jira/browse/SHIRO-399">SHIRO-399</a>.
     */
    @Test
    public void testNoMemoryLeakOnInvalidSessions() throws Exception {
        SessionListener sessionListener = new SessionListener() {
            public void onStart(Session session) {
                session.setAttribute("I love", "Romania");
            }

            public void onStop(Session session) {
                tryToCleanSession(session);
            }

            public void onExpiration(Session session) {
                tryToCleanSession(session);
            }

            private void tryToCleanSession(Session session) {
                Collection<Object> keys = session.getAttributeKeys();
                for (Object key : keys) {
                    session.removeAttribute(key);
                }
            }
        };

        DefaultSessionManager sessionManager = new DefaultSessionManager();
        sessionManager.setSessionListeners(Arrays.asList(sessionListener));

        Session session = sessionManager.start(null);
        assertEquals(1, sessionManager.getActiveSessions().size());

        session.setTimeout(0L);
        //last access timestamp needs to be older than the current timestamp when validating, so ensure a delay:
        Thread.sleep(1);

        sessionManager.validateSessions();

        assertEquals(0, sessionManager.getActiveSessions().size());
    }
}
