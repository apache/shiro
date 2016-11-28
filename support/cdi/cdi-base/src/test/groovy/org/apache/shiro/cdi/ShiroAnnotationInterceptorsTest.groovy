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
package org.apache.shiro.cdi

import org.apache.deltaspike.testcontrol.api.junit.CdiTestRunner
import org.apache.shiro.authz.UnauthenticatedException
import org.apache.shiro.authz.UnauthorizedException
import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith

import javax.inject.Inject

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Tests for {@link ShiroAnnotationInterceptor}.
 */
@RunWith(CdiTestRunner.class)
public class ShiroAnnotationInterceptorsTest {

    @Inject
    private AnnotationTestStub stub

    @Test
    void doRequiresAuthenticationTrue() {

        def subject = mock(Subject)

        expect(subject.isAuthenticated()).andReturn(true);
        replay subject

        ThreadContext.bind(subject)

        assertEquals("Test Me", stub.doRequiresAuthentication("Test Me"))

        verify subject
    }

    @Test
    void doRequiresAuthenticationFalse() {

        def subject = mock(Subject)

        expect(subject.isAuthenticated()).andReturn(false);
        replay subject

        ThreadContext.bind(subject)

        try {
            stub.doRequiresAuthentication("Test Me")
            fail("expected UnauthenticatedException")
        }
        catch(UnauthenticatedException e) {
            // expected
        }

        verify subject
    }

    @Test
    void doRequiresUserTrue() {
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn("principal");
        replay subject

        ThreadContext.bind(subject)

        assertTrue stub.doRequiresUser()

        verify subject
    }

    @Test
    void doRequiresUserFalse() {

        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn(null);
        replay subject

        ThreadContext.bind(subject)

        try {
            stub.doRequiresUser()
            fail("expected UnauthenticatedException")
        }
        catch(UnauthenticatedException e) {
            // expected
        }

        verify subject
    }

    @Test
    void doRequiresGuestTrue() {
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn(null);
        replay subject

        ThreadContext.bind(subject)

        assertTrue stub.doRequiresGuest()

        verify subject
    }

    @Test
    void doRequiresGuestFalse() {

        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn("principal");
        replay subject

        ThreadContext.bind(subject)

        try {
            stub.doRequiresGuest()
            fail("expected UnauthenticatedException")
        }
        catch(UnauthenticatedException e) {
            // expected
        }

        verify subject
    }


    @Test
    void doRequiresRolesTrue() {
        def subject = mock(Subject)

        subject.checkRoles(Arrays.asList("RoleOne", "RoleTwo"))
        replay subject

        ThreadContext.bind(subject)

        assertTrue stub.doRequiresRoles()

        verify subject
    }

    @Test
    void doRequiresRolesFalse() {

        def subject = mock(Subject)

        subject.checkRoles(Arrays.asList("RoleOne", "RoleTwo"))
        expectLastCall().andThrow(new UnauthorizedException("Expected test exception") )
        replay subject

        ThreadContext.bind(subject)

        try {
            stub.doRequiresRoles()
            fail("expected UnauthorizedException")
        }
        catch(UnauthorizedException e) {
            // expected
        }

        verify subject
    }

    @Test
    void doRequiresPermissionsTrue() {
        def subject = mock(Subject)

        subject.checkPermissions("priv:one", "priv:two")
        replay subject

        ThreadContext.bind(subject)

        assertEquals "true", stub.doRequiresPermissions()

        verify subject
    }

    @Test
    void doRequiresPermissionsFalse() {

        def subject = mock(Subject)

        subject.checkPermissions("priv:one", "priv:two")
        expectLastCall().andThrow(new UnauthorizedException("Expected test exception") )
        replay subject

        ThreadContext.bind(subject)

        try {
            stub.doRequiresPermissions()
            fail("expected UnauthorizedException")
        }
        catch(UnauthorizedException e) {
            // expected
        }

        verify subject
    }

    @After
    void cleanupThread() {
        ThreadContext.unbindSubject();
    }

}
