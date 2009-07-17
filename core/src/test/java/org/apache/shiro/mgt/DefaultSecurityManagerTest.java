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
package org.apache.shiro.mgt;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.realm.text.PropertiesRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractValidatingSessionManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;


/**
 * @author Les Hazlewood
 * @since 0.2
 */
public class DefaultSecurityManagerTest {

    DefaultSecurityManager sm = null;

    @Before
    public void setup() {
        ThreadContext.clear();
        sm = new DefaultSecurityManager();
        sm.setRealm(new PropertiesRealm());
        SecurityUtils.setSecurityManager(sm);
    }

    @After
    public void tearDown() {
        SecurityUtils.setSecurityManager(null);
        sm.destroy();
        ThreadContext.clear();
    }

    @Test
    public void testDefaultConfig() {
        Subject subject = SecurityUtils.getSubject();

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

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-46">JSEC-46</a>
     */
    @Test
    public void testAutoCreateSessionAfterInvalidation() {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();
        Serializable origSessionId = session.getId();

        String key = "foo";
        String value1 = "bar";
        session.setAttribute(key, value1);
        assertEquals(value1, session.getAttribute(key));

        //now test auto creation:
        session.setTimeout(100);
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            //ignored
        }
        session.setTimeout(AbstractValidatingSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
        Serializable newSessionId = session.getId();
        assertFalse(origSessionId.equals(newSessionId));

        Object aValue = session.getAttribute(key);
        assertNull(aValue);
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-22">JSEC-22</a>
     */
    @Test
    public void testSubjectReuseAfterLogout() {

        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertTrue(subject.isAuthenticated());
        assertTrue("guest".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("guest"));

        Session session = subject.getSession();
        Serializable firstSessionId = session.getId();

        session.setAttribute("key", "value");
        assertEquals(session.getAttribute("key"), "value");

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());

        subject.login(new UsernamePasswordToken("lonestarr", "vespa"));
        assertTrue(subject.isAuthenticated());
        assertTrue("lonestarr".equals(subject.getPrincipal()));
        assertTrue(subject.hasRole("goodguy"));

        assertNotNull(subject.getSession());
        assertFalse(firstSessionId.equals(subject.getSession().getId()));

        subject.logout();

        assertNull(subject.getSession(false));
        assertNull(subject.getPrincipal());
        assertNull(subject.getPrincipals());

    }
}
