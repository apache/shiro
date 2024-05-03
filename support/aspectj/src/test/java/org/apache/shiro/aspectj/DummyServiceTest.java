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
import org.apache.shiro.env.BasicIniEnvironment;
import org.apache.shiro.subject.Subject;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

/**
 *
 */
@SuppressWarnings("checkstyle:MethodName")
public class DummyServiceTest {

    private static DummyService securedService;
    private static DummyService restrictedService;

    private Subject subject;

    @BeforeAll
    public static void setUpClass() throws Exception {
        var basicIniEnvironment = new BasicIniEnvironment("classpath:shiroDummyServiceTest.ini");
        SecurityUtils.setSecurityManager(basicIniEnvironment.getSecurityManager());

        securedService = new SecuredDummyService();
        restrictedService = new RestrictedDummyService();
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
        //don't corrupt other test cases since this is static memory:
        SecurityUtils.setSecurityManager(null);
    }

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
        securedService.anonymous();
    }

    @Test
    void testAnonymous_asUser() throws Exception {
        loginAsUser();
        securedService.anonymous();
    }

    @Test
    void testAnonymous_asAdmin() throws Exception {
        loginAsAdmin();
        securedService.anonymous();
    }

    // TEST GUEST
    @Test
    void testGuest_asAnonymous() throws Exception {
        securedService.guest();
    }

    @Test
    void testGuest_asUser() throws Exception {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            loginAsUser();
            securedService.guest();
        });
    }

    @Test
    void testGuest_asAdmin() throws Exception {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            loginAsAdmin();
            securedService.guest();
        });
    }

    // TEST PEEK
    @Test
    void testPeek_asAnonymous() throws Exception {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            securedService.peek();
        });
    }

    @Test
    void testPeek_asUser() throws Exception {
        loginAsUser();
        securedService.peek();
    }

    @Test
    void testPeek_asAdmin() throws Exception {
        loginAsAdmin();
        securedService.peek();
    }

    // TEST RETRIEVE
    //UnauthenticatedException per SHIRO-146
    @Test
    void testRetrieve_asAnonymous() throws Exception {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            securedService.retrieve();
        });
    }

    @Test
    void testRetrieve_asUser() throws Exception {
        loginAsUser();
        securedService.retrieve();
    }

    @Test
    void testRetrieve_asAdmin() throws Exception {
        loginAsAdmin();
        securedService.retrieve();
    }

    // TEST CHANGE
    //UnauthenticatedException per SHIRO-146
    @Test
    void testChange_asAnonymous() throws Exception {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            securedService.change();
        });
    }

    @Test
    void testChange_asUser() throws Exception {
        assertThatExceptionOfType(UnauthorizedException.class).isThrownBy(() -> {
            loginAsUser();
            securedService.change();
        });
    }

    @Test
    void testChange_asAdmin() throws Exception {
        loginAsAdmin();
        securedService.change();
    }

    // TEST RETRIEVE RESTRICTED
    //UnauthenticatedException per SHIRO-146
    @Test
    void testRetrieveRestricted_asAnonymous() throws Exception {
        assertThatExceptionOfType(UnauthenticatedException.class).isThrownBy(() -> {
            restrictedService.retrieve();
        });
    }

    @Test
    void testRetrieveRestricted_asUser() throws Exception {
        assertThatExceptionOfType(UnauthorizedException.class).isThrownBy(() -> {
            loginAsUser();
            restrictedService.retrieve();
        });
    }

    @Test
    void testRetrieveRestricted_asAdmin() throws Exception {
        loginAsAdmin();
        restrictedService.retrieve();
    }

}
