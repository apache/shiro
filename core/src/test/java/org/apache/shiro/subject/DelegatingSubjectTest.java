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
package org.apache.shiro.subject;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.util.ThreadContext;
import static org.easymock.EasyMock.*;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.util.concurrent.Callable;


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

    @Test
    public void testExecuteCallable() {

        String username = "jsmith";

        SecurityManager securityManager = createNiceMock(SecurityManager.class);
        PrincipalCollection identity = new SimplePrincipalCollection(username, "testRealm");
        final Subject sourceSubject = new DelegatingSubject(identity, true, null, null, securityManager);

        assertNull(ThreadContext.getSubject());
        assertNull(ThreadContext.getSecurityManager());

        Callable<String> callable = new Callable<String>() {
            public String call() throws Exception {
                Subject callingSubject = SecurityUtils.getSubject();
                assertNotNull(callingSubject);
                assertNotNull(SecurityUtils.getSecurityManager());
                assertEquals(callingSubject, sourceSubject);
                return "Hello " + callingSubject.getPrincipal();
            }
        };
        String response = sourceSubject.execute(callable);

        assertNotNull(response);
        assertEquals("Hello " + username, response);

        assertNull(ThreadContext.getSubject());
        assertNull(ThreadContext.getSecurityManager());
    }

    @Test
    public void testExecuteRunnable() {

        String username = "jsmith";

        SecurityManager securityManager = createNiceMock(SecurityManager.class);
        PrincipalCollection identity = new SimplePrincipalCollection(username, "testRealm");
        final Subject sourceSubject = new DelegatingSubject(identity, true, null, null, securityManager);

        assertNull(ThreadContext.getSubject());
        assertNull(ThreadContext.getSecurityManager());

        Runnable runnable = new Runnable() {
            public void run() {
                Subject callingSubject = SecurityUtils.getSubject();
                assertNotNull(callingSubject);
                assertNotNull(SecurityUtils.getSecurityManager());
                assertEquals(callingSubject, sourceSubject);
            }
        };
        sourceSubject.execute(runnable);

        assertNull(ThreadContext.getSubject());
        assertNull(ThreadContext.getSecurityManager());
    }
}
