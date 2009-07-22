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

import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * Unit test for the {@link DelegatingSession} class.
 */
public class DelegatingSessionTest {

    DelegatingSession session = null;
    DefaultSessionManager sm = null;

    @Before
    public void setup() {
        ThreadContext.clear();
        sm = new DefaultSessionManager();
        Serializable sessionId = sm.start((InetAddress) null);
        this.session = new DelegatingSession(sm, sessionId);
    }

    @After
    public void tearDown() {
        sm.destroy();
        ThreadContext.clear();
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
        session.setTimeout(100);
        assertEquals(session.getTimeout(), 100);
        sleep(150);
        //now the underlying session should have been expired and a new one replaced by default.
        //so ensure the replaced session has the default session timeout:
        assertEquals(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT, session.getTimeout());
        assertFalse(origId.equals(session.getId())); //new ID would have been generated
    }

}
