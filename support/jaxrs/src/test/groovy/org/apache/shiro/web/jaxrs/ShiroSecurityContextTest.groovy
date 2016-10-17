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
package org.apache.shiro.web.jaxrs

import org.apache.shiro.subject.SimplePrincipalCollection
import org.apache.shiro.subject.Subject
import org.apache.shiro.util.ThreadContext
import org.junit.After
import org.junit.Test

import javax.ws.rs.container.ContainerRequestContext
import javax.ws.rs.core.SecurityContext
import java.security.Principal

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Tests for {@link ShiroSecurityContext}.
 * @since 1.4
 */
class ShiroSecurityContextTest {

    @Test
    void testIsSecure() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)

        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(originalSecurityContext.isSecure()).andReturn(true)
        replay requestContext, originalSecurityContext

        assertTrue shrioContext.isSecure()

        verify requestContext, originalSecurityContext
    }

    @Test
    void testGetAuthenticationScheme() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)

        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(originalSecurityContext.getAuthenticationScheme()).andReturn("https")
        replay requestContext, originalSecurityContext

        assertEquals "https", shrioContext.getAuthenticationScheme()

        verify requestContext, originalSecurityContext
    }

    @Test
    void testGetUserPrincipalWithString() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn("TestUser")
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(subject.getPrincipals()).andReturn(new SimplePrincipalCollection("TestUser", "realm"))

        replay requestContext, originalSecurityContext, subject

        ThreadContext.bind(subject)

        def resultPrincipal = shrioContext.getUserPrincipal()
        assertSame "TestUser", resultPrincipal.getName()

        verify requestContext, originalSecurityContext, subject
    }

    @Test
    void testGetUserPrincipalNoPrincipal() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn(null)
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(subject.getPrincipals()).andReturn(null)
        expect(originalSecurityContext.getUserPrincipal()).andReturn(null)

        replay requestContext, originalSecurityContext, subject

        ThreadContext.bind(subject)

        assertNull shrioContext.getUserPrincipal()

        verify requestContext, originalSecurityContext, subject
    }

    @Test
    void testGetUserPrincipalPrincipalObject() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)
        def subject = mock(Subject)
        def testPrincipal = new TestPrincipal("Tester")

        expect(subject.getPrincipal()).andReturn(testPrincipal)
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(subject.getPrincipals()).andReturn(new SimplePrincipalCollection(testPrincipal, "test-realm"))

        replay requestContext, originalSecurityContext, subject

        ThreadContext.bind(subject)

        def resultPrincipal = shrioContext.getUserPrincipal()
        assertSame "Tester", resultPrincipal.getName()

        verify requestContext, originalSecurityContext, subject
    }

    @Test
    void testUserInRoleTrue() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn("test-principal")
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(subject.hasRole("test-role")).andReturn(true)

        replay requestContext, originalSecurityContext, subject

        ThreadContext.bind(subject)

        assertTrue shrioContext.isUserInRole("test-role")

        verify requestContext, originalSecurityContext, subject
    }

    @Test
    void testUserInRoleFalse() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn("test-principal")
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(subject.hasRole("test-role")).andReturn(false)

        replay requestContext, originalSecurityContext, subject

        ThreadContext.bind(subject)

        assertFalse shrioContext.isUserInRole("test-role")

        verify requestContext, originalSecurityContext, subject
    }

    @Test
    void testPrincipalEquals() {
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        def shrioContext = new ShiroSecurityContext(requestContext)
        def subject = mock(Subject)

        expect(subject.getPrincipal()).andReturn(null) // we are just testing equality here
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext).anyTimes()
        expect(subject.getPrincipals()).andReturn(new SimplePrincipalCollection("Tester", "test-realm"))
        expect(subject.getPrincipals()).andReturn(new SimplePrincipalCollection("Tester", "test-realm"))

        replay requestContext, originalSecurityContext, subject

        ThreadContext.bind(subject)

        def result1Principal = shrioContext.getUserPrincipal()
        def result2Principal = shrioContext.getUserPrincipal()

        assertEquals result1Principal, result2Principal
        assertNotSame result1Principal, result2Principal

        verify requestContext, originalSecurityContext, subject
    }

    @After
    void cleanUp() {
        ThreadContext.remove()
    }

    class TestPrincipal implements Principal {

        final String name;

        TestPrincipal(String name) {
            this.name = name
        }

        @Override
        String getName() {
            return name
        }
    }
}
