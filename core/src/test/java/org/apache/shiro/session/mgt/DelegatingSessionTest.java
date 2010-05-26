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

import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Unit test for the {@link DelegatingSession} class.
 */
public class DelegatingSessionTest {

    DelegatingSession session = null;
    DefaultSessionManager sm = null;

    @Before
    public void setup() {
        ThreadContext.remove();
        sm = new DefaultSessionManager();
        this.session = new DelegatingSession(sm, new DefaultSessionKey(sm.start(null).getId()));
    }

    @After
    public void tearDown() {
        sm.destroy();
        ThreadContext.remove();
    }

    public void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void testTimeout() {
        Serializable origId = session.getId();
        assertEquals(session.getTimeout(), AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
        session.touch();
        session.setTimeout(100);
        assertEquals(100, session.getTimeout());
        sleep(150);
        try {
            session.getTimeout();
            fail("Session should have expired.");
        } catch (ExpiredSessionException expected) {
        }
    }

}
