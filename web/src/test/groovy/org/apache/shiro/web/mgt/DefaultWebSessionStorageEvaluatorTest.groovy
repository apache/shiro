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
package org.apache.shiro.web.mgt

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.apache.shiro.session.Session
import org.apache.shiro.subject.Subject
import org.apache.shiro.subject.support.DefaultSubjectContext
import org.apache.shiro.web.subject.WebSubject
import org.apache.shiro.web.util.RequestPairSource
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link DefaultWebSessionStorageEvaluator} implementation.
 *
 * @since 1.2
 */
class DefaultWebSessionStorageEvaluatorTest {

    @Test
    void testWithSession() {

        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator()

        def subject = createStrictMock(Subject)
        def session = createStrictMock(Session)

        expect(subject.getSession(false)).andReturn session

        replay subject, session

        assertTrue evaluator.isSessionStorageEnabled(subject)

        verify subject, session
    }

    @Test
    void testWithoutSessionAndNonWebSubject() {

        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator()

        def subject = createStrictMock(Subject)

        expect(subject.getSession(false)).andReturn null

        replay subject

        assertTrue evaluator.isSessionStorageEnabled(subject)

        verify subject
    }

    @Test
    void testWithoutSessionAndGenerallyDisabled() {

        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator()
        evaluator.sessionStorageEnabled = false

        def subject = createStrictMock(Subject)

        expect(subject.getSession(false)).andReturn null

        replay subject

        assertFalse evaluator.isSessionStorageEnabled(subject)

        verify subject
    }

    @Test
    void testWebSubjectWithoutSessionAndGenerallyEnabled() {

        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator()

        def subject = createStrictMock(RequestPairWebSubject)
        def request = createMock(ServletRequest)
        def response = createMock(ServletResponse)

        expect(subject.getSession(false)).andReturn null
        expect(subject.getServletRequest()).andReturn request
        expect(request.getAttribute(eq(DefaultSubjectContext.SESSION_CREATION_ENABLED))).andReturn null

        replay subject, request, response

        assertTrue evaluator.isSessionStorageEnabled(subject)

        verify subject, request, response
    }

    @Test
    void testWebSubjectWithoutSessionAndGenerallyEnabledButRequestDisabled() {

        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator()

        def subject = createStrictMock(RequestPairWebSubject)
        def request = createMock(ServletRequest)
        def response = createMock(ServletResponse)

        expect(subject.getSession(false)).andReturn null
        expect(subject.getServletRequest()).andReturn request
        expect(request.getAttribute(eq(DefaultSubjectContext.SESSION_CREATION_ENABLED))).andReturn Boolean.FALSE

        replay subject, request, response

        assertFalse evaluator.isSessionStorageEnabled(subject)

        verify subject, request, response
    }

    @Test
    void testWebSubjectWithoutSessionAndGenerallyEnabledWithNonBooleanRequestAttribute() {

        DefaultWebSessionStorageEvaluator evaluator = new DefaultWebSessionStorageEvaluator()

        def subject = createStrictMock(RequestPairWebSubject)
        def request = createMock(ServletRequest)
        def response = createMock(ServletResponse)

        expect(subject.getSession(false)).andReturn null
        expect(subject.getServletRequest()).andReturn request
        expect(request.getAttribute(eq(DefaultSubjectContext.SESSION_CREATION_ENABLED))).andReturn new Object()

        replay subject, request, response

        assertTrue evaluator.isSessionStorageEnabled(subject)

        verify subject, request, response
    }

    private interface RequestPairWebSubject extends RequestPairSource, WebSubject {

    }
}
