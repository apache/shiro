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
import org.apache.shiro.UnavailableSecurityManagerException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.Ini;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractValidatingSessionManager;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.util.ThreadContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.Serializable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;


/**
 * @since 0.2
 */
public class DefaultSecurityManagerTest extends AbstractSecurityManagerTest {

    DefaultSecurityManager sm;

    @BeforeEach
    public void setup() {
        sm = new DefaultSecurityManager();
        Ini ini = new Ini();
        Ini.Section section = ini.addSection(IniRealm.USERS_SECTION_NAME);
        section.put("guest", "guest, guest");
        section.put("lonestarr", "vespa, goodguy");
        sm.setRealm(new IniRealm(ini));
        SecurityUtils.setSecurityManager(sm);
    }

    @AfterEach
    public void tearDown() {
        SecurityUtils.setSecurityManager(null);
        sm.destroy();
        super.tearDown();
    }

    @Test
    void testDefaultConfig() {
        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertThat(subject.isAuthenticated()).isTrue();
        assertThat(subject.getPrincipal()).isEqualTo("guest");
        assertThat(subject.hasRole("guest")).isTrue();

        Session session = subject.getSession();
        session.setAttribute("key", "value");
        assertThat(session.getAttribute("key")).isEqualTo("value");

        subject.logout();

        assertThat(subject.getSession(false)).isNull();
        assertThat(subject.getPrincipal()).isNull();
        assertThat(subject.getPrincipals()).isNull();
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-46">JSEC-46</a>
     */
    @SuppressWarnings("checkstyle:MagicNumber")
    @Test
    void testAutoCreateSessionAfterInvalidation() {
        Subject subject = SecurityUtils.getSubject();
        Session session = subject.getSession();

        String key = "foo";
        String value1 = "bar";
        session.setAttribute(key, value1);
        assertThat(session.getAttribute(key)).isEqualTo(value1);

        //now test auto creation:
        session.setTimeout(50);
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            //ignored
        }
        try {
            session.setTimeout(AbstractValidatingSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
            fail("Session should have expired.");
        } catch (ExpiredSessionException expected) {
        }
    }

    /**
     * Test that validates functionality for issue
     * <a href="https://issues.apache.org/jira/browse/JSEC-22">JSEC-22</a>
     */
    @Test
    void testSubjectReuseAfterLogout() {

        Subject subject = SecurityUtils.getSubject();

        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertThat(subject.isAuthenticated()).isTrue();
        assertThat(subject.getPrincipal()).isEqualTo("guest");
        assertThat(subject.hasRole("guest")).isTrue();

        Session session = subject.getSession();
        Serializable firstSessionId = session.getId();

        session.setAttribute("key", "value");
        assertThat(session.getAttribute("key")).isEqualTo("value");

        subject.logout();

        assertThat(subject.getSession(false)).isNull();
        assertThat(subject.getPrincipal()).isNull();
        assertThat(subject.getPrincipals()).isNull();

        subject.login(new UsernamePasswordToken("lonestarr", "vespa"));
        assertThat(subject.isAuthenticated()).isTrue();
        assertThat(subject.getPrincipal()).isEqualTo("lonestarr");
        assertThat(subject.hasRole("goodguy")).isTrue();

        assertThat(subject.getSession()).isNotNull();
        assertThat(subject.getSession().getId()).isNotEqualTo(firstSessionId);

        subject.logout();

        assertThat(subject.getSession(false)).isNull();
        assertThat(subject.getPrincipal()).isNull();
        assertThat(subject.getPrincipals()).isNull();

    }

    /**
     * Test ensures that a {@link Subject#login(AuthenticationToken)} first uses
     * the {@link SecurityManager} passed to its {@link Subject.Builder}
     * (if one was) instead of the one found in either the {@link ThreadContext}
     * or statically in {@link SecurityUtils}, either of which may not exist.
     * <a href="https://issues.apache.org/jira/browse/SHIRO-457">SHIRO-457</a>
     */
    @Test
    void testNewSubjectWithoutThreadSecurityManager() {
        // Ensure no fallback sm exists in thread context or statically
        SecurityUtils.setSecurityManager(null);
        try {
            SecurityUtils.getSecurityManager();
        } catch (UnavailableSecurityManagerException e) {
            assertThat(e.getMessage()).startsWith("No SecurityManager accessible");
        }

        // Specify sm to use and build subject with
        DelegatingSubject subject =
                (DelegatingSubject) (new Subject.Builder(sm)).buildSubject();

        // Login and verify specified sm is used and no error thrown
        AuthenticationToken token = new UsernamePasswordToken("guest", "guest");
        subject.login(token);
        assertThat(subject.getSecurityManager()).isEqualTo(sm);
    }

    @Test
    void testNewSubjectWithoutSessionCreationEnabled() {
        SimplePrincipalCollection principals = new SimplePrincipalCollection("guest", "asd");
        Subject subject = new Subject.Builder().principals(principals).sessionCreationEnabled(false).buildSubject();

        assertThat(subject.getPrincipal()).isEqualTo("guest");
    }
}
