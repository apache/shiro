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
package org.apache.shiro.authc.credential

import org.apache.shiro.authc.AuthenticationInfo
import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.crypto.hash.Sha256Hash
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link PasswordMatcher} implementation.
 *
 * @since 1.2
 */
class PasswordMatcherTest {

    @Test
    void testMissingPasswordService() {
        def matcher = new PasswordMatcher()
        matcher.passwordService = null
        try {
            matcher.doCredentialsMatch(null, null)
            fail "Test should fail due to lack of a configured PasswordService instance."
        } catch (IllegalStateException expected) {
        }
    }

    @Test
    void testStringPasswordComparison() {
        def service = createMock(PasswordService)
        def token = createMock(AuthenticationToken)
        def info = createMock(AuthenticationInfo)
        //generate a stored password just for this test:
        def submittedPassword = "plaintext"
        def savedPassword = "encrypted"

        expect(token.credentials).andReturn submittedPassword
        expect(info.credentials).andReturn savedPassword

        expect(service.passwordsMatch(eq(submittedPassword), eq(savedPassword))).andReturn true

        replay token, info, service

        def matcher = new PasswordMatcher()
        matcher.passwordService = service
        assertSame service, matcher.passwordService

        assertTrue matcher.doCredentialsMatch(token, info)

        verify token, info, service
    }

    @Test
    void testHashComparisonWithoutHashedPasswordService() {
        def service = createMock(PasswordService)
        def token = createMock(AuthenticationToken)
        def info = createMock(AuthenticationInfo)
        //generate a stored password just for this test:
        def submittedPassword = "plaintext"
        def savedPassword = new Sha256Hash("plaintext")

        expect(token.credentials).andReturn submittedPassword
        expect(info.credentials).andReturn savedPassword

        replay token, info, service

        def matcher = new PasswordMatcher()
        matcher.passwordService = service
        assertSame service, matcher.passwordService

        try {
            assertTrue matcher.doCredentialsMatch(token, info)
            fail "matcher should fail since PasswordService is not a HashingPasswordService"
        } catch (IllegalStateException expected) {
        }

        verify token, info, service
    }

    @Test
    void testHashComparison() {
        def service = createMock(HashingPasswordService)
        def token = createMock(AuthenticationToken)
        def info = createMock(AuthenticationInfo)
        //generate a stored password just for this test:
        def submittedPassword = "plaintext"
        def savedPassword = new Sha256Hash("plaintext")

        expect(token.credentials).andReturn submittedPassword
        expect(info.credentials).andReturn savedPassword

        expect(service.passwordsMatch(submittedPassword, savedPassword)).andReturn true

        replay token, info, service

        def matcher = new PasswordMatcher()
        matcher.passwordService = service
        assertSame service, matcher.passwordService

        assertTrue matcher.doCredentialsMatch(token, info)

        verify token, info, service
    }

    /**
     * Asserts fix for https://issues.apache.org/jira/browse/SHIRO-363
     */
    @Test
    void testCharArrayComparison() {
        def service = createMock(PasswordService)
        def token = createMock(AuthenticationToken)
        def info = createMock(AuthenticationInfo)
        //generate a stored password just for this test:
        def submittedPassword = "foo"
        def savedPasswordAsString = "foo";
        def savedPassword = savedPasswordAsString.toCharArray()

        expect(token.credentials).andReturn submittedPassword
        expect(info.credentials).andReturn savedPassword

        expect(service.passwordsMatch(eq(submittedPassword), eq(savedPasswordAsString))).andReturn true

        replay token, info, service

        def matcher = new PasswordMatcher()
        matcher.passwordService = service
        assertSame service, matcher.passwordService

        assertTrue matcher.doCredentialsMatch(token, info)

        verify token, info, service
    }

    @Test
    void testUnexpectedSavedCredentialsType() {
        def service = createMock(HashingPasswordService)
        def token = createMock(AuthenticationToken)
        def info = createMock(AuthenticationInfo)
        //generate a stored password just for this test:
        def submittedPassword = "plaintext"
        def savedPassword = 23

        expect(token.credentials).andReturn submittedPassword
        expect(info.credentials).andReturn savedPassword

        replay token, info, service

        def matcher = new PasswordMatcher()
        matcher.passwordService = service
        assertSame service, matcher.passwordService

        try {
            assertTrue matcher.doCredentialsMatch(token, info)
            fail "Saved credentials should be either a String or Hash instance."
        } catch (IllegalArgumentException expected) {
        }

        verify token, info, service

    }

}
