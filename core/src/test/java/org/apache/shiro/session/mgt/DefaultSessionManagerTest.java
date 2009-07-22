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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.net.InetAddress;

/**
 * Unit test for the {@link DefaultSessionManager DefaultSessionManager} implementation.
 */
public class DefaultSessionManagerTest {

    DefaultSessionManager sm = null;

    @Before
    public void setup() {
        ThreadContext.clear();
        sm = new DefaultSessionManager();
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
    public void testGlobalTimeout() {
        sm.setGlobalSessionTimeout(100);
        Serializable sessionId = sm.start((InetAddress) null);
        assertTrue(sm.isValid(sessionId));
        sleep(150);
        assertFalse(sm.isValid(sessionId));
    }
}
