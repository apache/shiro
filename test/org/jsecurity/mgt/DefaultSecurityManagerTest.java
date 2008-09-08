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
package org.jsecurity.mgt;

import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.session.Session;
import org.jsecurity.subject.Subject;
import org.jsecurity.util.ThreadContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class DefaultSecurityManagerTest {

    DefaultSecurityManager sm = null;

    @Before
    public void setup() {
        sm = new DefaultSecurityManager();
        ThreadContext.clear();
    }

    @After
    public void tearDown() {
        sm.destroy();
        ThreadContext.clear();
    }

    @Test
    public void testDefaultConfig() {
        Subject subject = sm.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertTrue(subject.isAuthenticated());
        assertTrue("guest".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("guest"));

        Session session = subject.getSession();
        session.setAttribute("key", "value");
        assertEquals(session.getAttribute("key"), "value");

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());
    }
}
