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
package org.ki.subject;

import org.ki.mgt.DefaultSecurityManager;
import org.ki.session.Session;
import org.ki.util.ThreadContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;

/**
 * @author Les Hazlewood
 * @since Aug 1, 2008 2:11:17 PM
 */
public class DelegatingSubjectTest {

    @Before
    public void setup() {
        ThreadContext.clear();
    }

    @After
    public void tearDown() {
        ThreadContext.clear();
    }

    @Test
    public void testSessionStopThenStart() {
        String key = "testKey";
        String value = "testValue";
        DefaultSecurityManager sm = new DefaultSecurityManager();

        DelegatingSubject subject = new DelegatingSubject(sm);

        Session session = subject.getSession();
        session.setAttribute(key, value);
        assertTrue(session.getAttribute(key).equals(value));
        Serializable firstSessionId = session.getId();
        assertNotNull(firstSessionId);

        session.stop();

        session = subject.getSession();
        assertNotNull(session);
        assertNull(session.getAttribute(key));
        Serializable secondSessionId = session.getId();
        assertNotNull(secondSessionId);
        assertFalse(firstSessionId.equals(secondSessionId));

        subject.logout();

        sm.destroy();
    }
}
