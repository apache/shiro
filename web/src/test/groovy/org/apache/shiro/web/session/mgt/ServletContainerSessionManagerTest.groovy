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
package org.apache.shiro.web.session.mgt

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession
import org.apache.shiro.session.mgt.SessionContext
import org.apache.shiro.session.mgt.SessionKey
import org.apache.shiro.web.session.HttpServletSession
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link ServletContainerSessionManager} implementation.
 */
class ServletContainerSessionManagerTest {

    @Test
    void testStartWithNonWebSessionContext() {

        def sessionContext = createStrictMock(SessionContext)

        replay sessionContext

        ServletContainerSessionManager mgr = new ServletContainerSessionManager()
        try {
            mgr.start sessionContext
            fail "Start should have failed with a non-web SessionContext"
        } catch (IllegalArgumentException expected) {
        }

        verify sessionContext
    }

    @Test
    void testStartWithContextHostValue() {

        def host = "host.somecompany.com"

        def request = createStrictMock(HttpServletRequest)
        def response = createStrictMock(HttpServletResponse)
        def httpSession = createStrictMock(HttpSession)
        def context = new DefaultWebSessionContext()
        context.servletRequest = request
        context.servletResponse = response
        context.host = host

        expect(request.session).andReturn httpSession

        httpSession.setAttribute(eq(HttpServletSession.HOST_SESSION_KEY), eq(host))
        expect(httpSession.getAttribute(eq(HttpServletSession.HOST_SESSION_KEY))).andReturn host

        replay request, response, httpSession

        ServletContainerSessionManager mgr = new ServletContainerSessionManager()
        def startedSession = mgr.start(context)

        assertTrue startedSession instanceof HttpServletSession
        assertEquals host, startedSession.host
        assertSame httpSession, startedSession.httpSession

        verify request, response, httpSession
    }

    @Test
    void testStartWithoutContextHostValue() {

        def host = "host.somecompany.com"

        def request = createStrictMock(HttpServletRequest)
        def response = createStrictMock(HttpServletResponse)
        def httpSession = createStrictMock(HttpSession)
        def context = new DefaultWebSessionContext()
        context.servletRequest = request
        context.servletResponse = response

        expect(request.session).andReturn httpSession
        expect(request.remoteHost).andReturn host

        httpSession.setAttribute(eq(HttpServletSession.HOST_SESSION_KEY), eq(host))
        expect(httpSession.getAttribute(eq(HttpServletSession.HOST_SESSION_KEY))).andReturn host

        replay request, response, httpSession

        ServletContainerSessionManager mgr = new ServletContainerSessionManager()
        def startedSession = mgr.start(context)

        assertTrue startedSession instanceof HttpServletSession
        assertEquals host, startedSession.host
        assertSame httpSession, startedSession.httpSession

        verify request, response, httpSession
    }

    @Test
    void testGetSessionWithNonWebSessionKey() {

        def key = createStrictMock(SessionKey)

        replay key

        ServletContainerSessionManager mgr = new ServletContainerSessionManager()
        try {
            mgr.getSession(key)
            fail "getSession should have failed with a non-web SessionKey"
        } catch (IllegalArgumentException expected) {
        }

        verify key
    }

    @Test
    void testGetSessionWithExistingRequestSession() {

        String host = "www.company.com"

        def request = createStrictMock(HttpServletRequest)
        def response = createStrictMock(HttpServletResponse)
        def httpSession = createStrictMock(HttpSession)

        expect(request.getSession(false)).andReturn httpSession
        expect(request.remoteHost).andReturn host
        httpSession.setAttribute(eq(HttpServletSession.HOST_SESSION_KEY), eq(host))
        expect(httpSession.getAttribute(eq(HttpServletSession.HOST_SESSION_KEY))).andReturn host

        def key = new WebSessionKey(request, response)

        replay request, response, httpSession

        ServletContainerSessionManager mgr = new ServletContainerSessionManager()
        def session = mgr.getSession(key)

        assertTrue session instanceof HttpServletSession
        assertEquals host, session.host
        assertSame httpSession, session.httpSession

        verify request, response, httpSession
    }

    @Test
    void testGetSessionWithoutExistingRequestSession() {

        def request = createStrictMock(HttpServletRequest)
        def response = createStrictMock(HttpServletResponse)
        def httpSession = createStrictMock(HttpSession)

        expect(request.getSession(false)).andReturn null

        def key = new WebSessionKey(request, response)

        replay request, response, httpSession

        ServletContainerSessionManager mgr = new ServletContainerSessionManager()
        def session = mgr.getSession(key)

        assertNull session

        verify request, response, httpSession
    }





}
