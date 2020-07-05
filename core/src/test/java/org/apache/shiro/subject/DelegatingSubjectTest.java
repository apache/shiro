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
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.ini.IniSecurityManagerFactory;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.lang.util.LifecycleUtils;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;
import java.util.concurrent.Callable;

import static org.easymock.EasyMock.createNiceMock;
import static org.junit.Assert.*;


/**
 * @since Aug 1, 2008 2:11:17 PM
 */
public class DelegatingSubjectTest {

    @Before
    public void setup() {
        ThreadContext.remove();
    }

    @After
    public void tearDown() {
        ThreadContext.remove();
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

    @Test
    public void testRunAs() {

        Ini ini = new Ini();
        Ini.Section users = ini.addSection("users");
        users.put("user1", "user1,role1");
        users.put("user2", "user2,role2");
        users.put("user3", "user3,role3");
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory(ini);
        SecurityManager sm = factory.getInstance();

        //login as user1
        Subject subject = new Subject.Builder(sm).buildSubject();
        subject.login(new UsernamePasswordToken("user1", "user1"));

        assertFalse(subject.isRunAs());
        assertEquals("user1", subject.getPrincipal());
        assertTrue(subject.hasRole("role1"));
        assertFalse(subject.hasRole("role2"));
        assertFalse(subject.hasRole("role3"));
        assertNull(subject.getPreviousPrincipals()); //no previous principals since we haven't called runAs yet

        //runAs user2:
        subject.runAs(new SimplePrincipalCollection("user2", IniSecurityManagerFactory.INI_REALM_NAME));
        assertTrue(subject.isRunAs());
        assertEquals("user2", subject.getPrincipal());
        assertTrue(subject.hasRole("role2"));
        assertFalse(subject.hasRole("role1"));
        assertFalse(subject.hasRole("role3"));

        //assert we still have the previous (user1) principals:
        PrincipalCollection previous = subject.getPreviousPrincipals();
        assertFalse(previous == null || previous.isEmpty());
        assertTrue(previous.getPrimaryPrincipal().equals("user1"));

        //test the stack functionality:  While as user2, run as user3:
        subject.runAs(new SimplePrincipalCollection("user3", IniSecurityManagerFactory.INI_REALM_NAME));
        assertTrue(subject.isRunAs());
        assertEquals("user3", subject.getPrincipal());
        assertTrue(subject.hasRole("role3"));
        assertFalse(subject.hasRole("role1"));
        assertFalse(subject.hasRole("role2"));

        //assert we still have the previous (user2) principals in the stack:
        previous = subject.getPreviousPrincipals();
        assertFalse(previous == null || previous.isEmpty());
        assertTrue(previous.getPrimaryPrincipal().equals("user2"));

        //drop down to user2:
        subject.releaseRunAs();

        //assert still run as:
        assertTrue(subject.isRunAs());
        assertEquals("user2", subject.getPrincipal());
        assertTrue(subject.hasRole("role2"));
        assertFalse(subject.hasRole("role1"));
        assertFalse(subject.hasRole("role3"));

        //assert we still have the previous (user1) principals:
        previous = subject.getPreviousPrincipals();
        assertFalse(previous == null || previous.isEmpty());
        assertTrue(previous.getPrimaryPrincipal().equals("user1"));

        //drop down to original user1:
        subject.releaseRunAs();

        //assert we're no longer runAs:
        assertFalse(subject.isRunAs());
        assertEquals("user1", subject.getPrincipal());
        assertTrue(subject.hasRole("role1"));
        assertFalse(subject.hasRole("role2"));
        assertFalse(subject.hasRole("role3"));
        assertNull(subject.getPreviousPrincipals()); //no previous principals in orig state

        subject.logout();

        LifecycleUtils.destroy(sm);
    }

    @Test
    public void testToString() {
        // given
        String username = "jsmith";

        DefaultSecurityManager securityManager = new DefaultSecurityManager();
        PrincipalCollection identity = new SimplePrincipalCollection(username, "testRealm");
        final String hostname = "localhost";
        final DelegatingSubject sourceSubject = new DelegatingSubject(identity, true, hostname, null, securityManager);

        // when
        final String subjectToString = sourceSubject.toString();

        // then
        final Session session = sourceSubject.getSession(true);
        String sesionId = (String) session.getId();
        assertFalse("toString must not leak sessionId", subjectToString.contains(sesionId));
        assertFalse("toString must not leak host", subjectToString.contains(hostname));
    }

}
