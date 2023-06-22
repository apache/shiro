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
package org.apache.shiro.aspectj;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.ini.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.lang.util.Factory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 */
public class DummyServiceTest {

    private static DummyService SECURED_SERVICE;
    private static DummyService RESTRICTED_SERVICE;

    @BeforeAll
    public static void setUpClass() throws Exception {
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiroDummyServiceTest.ini");
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        SECURED_SERVICE = new SecuredDummyService();
        RESTRICTED_SERVICE = new RestrictedDummyService();
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
        //don't corrupt other test cases since this is static memory:
        SecurityUtils.setSecurityManager(null);
    }

    private Subject subject;

    @BeforeEach
    public void setUp() throws Exception {
        subject = SecurityUtils.getSubject();
    }

    @AfterEach
    public void tearDown() throws Exception {
        subject.logout();
    }

    private void loginAsUser() {
        subject.login(new UsernamePasswordToken("joe", "bob"));
    }

    private void loginAsAdmin() {
        subject.login(new UsernamePasswordToken("root", "secret"));
    }

    // TEST ANONYMOUS
    @Test
    void testAnonymous_asAnonymous() throws Exception {
        SECURED_SERVICE.anonymous();
    }

    @Test
    void testAnonymous_asUser() throws Exception {
        loginAsUser();
        SECURED_SERVICE.anonymous();
    }

    @Test
    void testAnonymous_asAdmin() throws Exception {
        loginAsAdmin();
        SECURED_SERVICE.anonymous();
    }

    // TEST GUEST
    @Test
    void testGuest_asAnonymous() throws Exception {
        SECURED_SERVICE.guest();
    }

    @Test
    void testGuest_asUser() throws Exception {
        assertThrows(UnauthenticatedException.class, () -> {
            loginAsUser();
            SECURED_SERVICE.guest();
        });
    }

    @Test
    void testGuest_asAdmin() throws Exception {
        assertThrows(UnauthenticatedException.class, () -> {
            loginAsAdmin();
            SECURED_SERVICE.guest();
        });
    }

    // TEST PEEK
    @Test
    void testPeek_asAnonymous() throws Exception {
        assertThrows(UnauthenticatedException.class, () -> {
            SECURED_SERVICE.peek();
        });
    }

    @Test
    void testPeek_asUser() throws Exception {
        loginAsUser();
        SECURED_SERVICE.peek();
    }

    @Test
    void testPeek_asAdmin() throws Exception {
        loginAsAdmin();
        SECURED_SERVICE.peek();
    }

    // TEST RETRIEVE
    //UnauthenticatedException per SHIRO-146
    @Test
    void testRetrieve_asAnonymous() throws Exception {
        assertThrows(UnauthenticatedException.class, () -> {
            SECURED_SERVICE.retrieve();
        });
    }

    @Test
    void testRetrieve_asUser() throws Exception {
        loginAsUser();
        SECURED_SERVICE.retrieve();
    }

    @Test
    void testRetrieve_asAdmin() throws Exception {
        loginAsAdmin();
        SECURED_SERVICE.retrieve();
    }

    // TEST CHANGE
    //UnauthenticatedException per SHIRO-146
    @Test
    void testChange_asAnonymous() throws Exception {
        assertThrows(UnauthenticatedException.class, () -> {
            SECURED_SERVICE.change();
        });
    }

    @Test
    void testChange_asUser() throws Exception {
        assertThrows(UnauthorizedException.class, () -> {
            loginAsUser();
            SECURED_SERVICE.change();
        });
    }

    @Test
    void testChange_asAdmin() throws Exception {
        loginAsAdmin();
        SECURED_SERVICE.change();
    }

    // TEST RETRIEVE RESTRICTED
    //UnauthenticatedException per SHIRO-146
    @Test
    void testRetrieveRestricted_asAnonymous() throws Exception {
        assertThrows(UnauthenticatedException.class, () -> {
            RESTRICTED_SERVICE.retrieve();
        });
    }

    @Test
    void testRetrieveRestricted_asUser() throws Exception {
        assertThrows(UnauthorizedException.class, () -> {
            loginAsUser();
            RESTRICTED_SERVICE.retrieve();
        });
    }

    @Test
    void testRetrieveRestricted_asAdmin() throws Exception {
        loginAsAdmin();
        RESTRICTED_SERVICE.retrieve();
    }

}
