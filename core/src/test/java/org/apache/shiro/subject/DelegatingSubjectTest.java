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
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.lang.util.LifecycleUtils;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.util.concurrent.Callable;

import static org.apache.shiro.env.BasicIniEnvironment.INI_REALM_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createNiceMock;

/**
 * @since Aug 1, 2008 2:11:17 PM
 */
public class DelegatingSubjectTest {

    @BeforeEach
    public void setup() {
        ThreadContext.remove();
    }

    @AfterEach
    public void tearDown() {
        ThreadContext.remove();
    }

    @Test
    void testSessionStopThenStart() {
        String key = "testKey";
        String value = "testValue";
        DefaultSecurityManager sm = new DefaultSecurityManager();

        DelegatingSubject subject = new DelegatingSubject(sm);

        Session session = subject.getSession();
        session.setAttribute(key, value);
        assertThat(value).isEqualTo(session.getAttribute(key));
        Serializable firstSessionId = session.getId();
        assertThat(firstSessionId).isNotNull();

        session.stop();

        session = subject.getSession();
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(key)).isNull();
        Serializable secondSessionId = session.getId();
        assertThat(secondSessionId).isNotNull();
        assertThat(secondSessionId).isNotEqualTo(firstSessionId);

        subject.logout();

        sm.destroy();
    }

    @Test
    void testExecuteCallable() {

        String username = "jsmith";

        SecurityManager securityManager = createNiceMock(SecurityManager.class);
        PrincipalCollection identity = new SimplePrincipalCollection(username, "testRealm");
        final Subject sourceSubject = new DelegatingSubject(identity, true, null, null, securityManager);

        assertThat(ThreadContext.getSubject()).isNull();
        assertThat(ThreadContext.getSecurityManager()).isNull();

        Callable<String> callable = new Callable<String>() {
            public String call() throws Exception {
                Subject callingSubject = SecurityUtils.getSubject();
                assertThat(callingSubject).isNotNull();
                assertThat(SecurityUtils.getSecurityManager()).isNotNull();
                assertThat(sourceSubject).isEqualTo(callingSubject);
                return "Hello " + callingSubject.getPrincipal();
            }
        };
        String response = sourceSubject.execute(callable);

        assertThat(response).isNotNull();
        assertThat(response).isEqualTo("Hello " + username);

        assertThat(ThreadContext.getSubject()).isNull();
        assertThat(ThreadContext.getSecurityManager()).isNull();
    }

    @Test
    void testExecuteRunnable() {

        String username = "jsmith";

        SecurityManager securityManager = createNiceMock(SecurityManager.class);
        PrincipalCollection identity = new SimplePrincipalCollection(username, "testRealm");
        final Subject sourceSubject = new DelegatingSubject(identity, true, null, null, securityManager);

        assertThat(ThreadContext.getSubject()).isNull();
        assertThat(ThreadContext.getSecurityManager()).isNull();

        Runnable runnable = new Runnable() {
            public void run() {
                Subject callingSubject = SecurityUtils.getSubject();
                assertThat(callingSubject).isNotNull();
                assertThat(SecurityUtils.getSecurityManager()).isNotNull();
                assertThat(sourceSubject).isEqualTo(callingSubject);
            }
        };
        sourceSubject.execute(runnable);

        assertThat(ThreadContext.getSubject()).isNull();
        assertThat(ThreadContext.getSecurityManager()).isNull();
    }

    @Test
    void testRunAs() {

        Ini ini = new Ini();
        Ini.Section users = ini.addSection("users");
        users.put("user1", "user1,role1");
        users.put("user2", "user2,role2");
        users.put("user3", "user3,role3");
        SecurityManager sm = new BasicIniEnvironment(ini).getSecurityManager();

        //login as user1
        Subject subject = new Subject.Builder(sm).buildSubject();
        subject.login(new UsernamePasswordToken("user1", "user1"));

        assertThat(subject.isRunAs()).isFalse();
        assertThat(subject.getPrincipal()).isEqualTo("user1");
        assertThat(subject.hasRole("role1")).isTrue();
        assertThat(subject.hasRole("role2")).isFalse();
        assertThat(subject.hasRole("role3")).isFalse();
        //no previous principals since we haven't called runAs yet
        assertThat(subject.getPreviousPrincipals()).isNull();

        //runAs user2:
        subject.runAs(new SimplePrincipalCollection("user2", INI_REALM_NAME));
        assertThat(subject.isRunAs()).isTrue();
        assertThat(subject.getPrincipal()).isEqualTo("user2");
        assertThat(subject.hasRole("role2")).isTrue();
        assertThat(subject.hasRole("role1")).isFalse();
        assertThat(subject.hasRole("role3")).isFalse();

        //assert we still have the previous (user1) principals:
        PrincipalCollection previous = subject.getPreviousPrincipals();
        assertThat(previous == null || previous.isEmpty()).isFalse();
        assertThat(previous.getPrimaryPrincipal()).isEqualTo("user1");

        //test the stack functionality:  While as user2, run as user3:
        subject.runAs(new SimplePrincipalCollection("user3", INI_REALM_NAME));
        assertThat(subject.isRunAs()).isTrue();
        assertThat(subject.getPrincipal()).isEqualTo("user3");
        assertThat(subject.hasRole("role3")).isTrue();
        assertThat(subject.hasRole("role1")).isFalse();
        assertThat(subject.hasRole("role2")).isFalse();

        //assert we still have the previous (user2) principals in the stack:
        previous = subject.getPreviousPrincipals();
        assertThat(previous == null || previous.isEmpty()).isFalse();
        assertThat(previous.getPrimaryPrincipal()).isEqualTo("user2");

        //drop down to user2:
        subject.releaseRunAs();

        //assert still run as:
        assertThat(subject.isRunAs()).isTrue();
        assertThat(subject.getPrincipal()).isEqualTo("user2");
        assertThat(subject.hasRole("role2")).isTrue();
        assertThat(subject.hasRole("role1")).isFalse();
        assertThat(subject.hasRole("role3")).isFalse();

        //assert we still have the previous (user1) principals:
        previous = subject.getPreviousPrincipals();
        assertThat(previous == null || previous.isEmpty()).isFalse();
        assertThat(previous.getPrimaryPrincipal()).isEqualTo("user1");

        //drop down to original user1:
        subject.releaseRunAs();

        //assert we're no longer runAs:
        assertThat(subject.isRunAs()).isFalse();
        assertThat(subject.getPrincipal()).isEqualTo("user1");
        assertThat(subject.hasRole("role1")).isTrue();
        assertThat(subject.hasRole("role2")).isFalse();
        assertThat(subject.hasRole("role3")).isFalse();
        //no previous principals in orig state
        assertThat(subject.getPreviousPrincipals()).isNull();

        subject.logout();

        LifecycleUtils.destroy(sm);
    }

    @Test
    void testToString() {
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
        String sessionId = (String) session.getId();
        assertThat(subjectToString.contains(sessionId)).as("toString must not leak sessionId").isFalse();
        assertThat(subjectToString.contains(hostname)).as("toString must not leak host").isFalse();
    }

}
