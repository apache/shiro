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
package org.apache.shiro.web.servlet

import org.junit.Test

import javax.servlet.ServletContext
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

import static org.junit.Assert.assertEquals
import static org.mockito.Mockito.*

/**
 * Unit tests for {@link ShiroHttpServletResponse}.
 */
class ShiroHttpServletResponseTest {

    private static String URL_SESSION_ID = "url_session_id"

    @Test
    void testEncodeURLNoSessionId() {

        def servletContext = mock(ServletContext)
        def httpServletResponse = mock(HttpServletResponse)
        def shiroHttpServletRequest = setupRequestMock()
        when(shiroHttpServletRequest.getSession(false)).then(args -> null)
        when(shiroHttpServletRequest.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)).then(args -> true)

        def shiroHttpServletResponse = new ShiroHttpServletResponse(httpServletResponse, servletContext, shiroHttpServletRequest)

        assertEquals "/foobar", shiroHttpServletResponse.encodeURL("/foobar")
        verify(shiroHttpServletRequest).getSession(false)
        verify(shiroHttpServletRequest).getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)
    }

    @Test
    void testEncodeURLSessionIdInURL() {

        def servletContext = mock(ServletContext)
        def httpServletResponse = mock(HttpServletResponse)
        def session = mock(HttpSession)
        def shiroHttpServletRequest = setupRequestMock()
        when(session.getId()).then(args -> URL_SESSION_ID)
        when(shiroHttpServletRequest.getSession(false)).then(args -> session)
        when(shiroHttpServletRequest.getSession()).then(args -> session)
        when(shiroHttpServletRequest.isRequestedSessionIdFromCookie()).then(args -> false)
        when(shiroHttpServletRequest.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)).then(args -> true)

        def shiroHttpServletResponse = new ShiroHttpServletResponse(httpServletResponse, servletContext, shiroHttpServletRequest)

        assertEquals "/foobar;JSESSIONID=" + URL_SESSION_ID, shiroHttpServletResponse.encodeURL("/foobar")
        verify(shiroHttpServletRequest).getSession(false)
        verify(shiroHttpServletRequest).getSession()
        verify(shiroHttpServletRequest).isRequestedSessionIdFromCookie()
        verify(shiroHttpServletRequest).getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)
        verify(session, times(2)).getId()
    }

    @Test
    void testEncodeURLSessionIdInCookie() {

        def servletContext = mock(ServletContext)
        def httpServletResponse = mock(HttpServletResponse)
        def session = mock(HttpSession)
        def shiroHttpServletRequest = setupRequestMock()
        when(shiroHttpServletRequest.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)).then(args -> false)

        def shiroHttpServletResponse = new ShiroHttpServletResponse(httpServletResponse, servletContext, shiroHttpServletRequest)

        assertEquals "/foobar", shiroHttpServletResponse.encodeURL("/foobar")
        verify(shiroHttpServletRequest).getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)
    }

    @Test
    void testEncodeURLSessionIdInWhenRewriteDisabled() {

        def servletContext = mock(ServletContext)
        def httpServletResponse = mock(HttpServletResponse)
        def session = mock(HttpSession)
        def shiroHttpServletRequest = setupRequestMock()
        when(shiroHttpServletRequest.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)).then(args -> false)

        def shiroHttpServletResponse = new ShiroHttpServletResponse(httpServletResponse, servletContext, shiroHttpServletRequest)

        assertEquals "/foobar", shiroHttpServletResponse.encodeURL("/foobar")
        verify(shiroHttpServletRequest).getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)
    }

    /**
     * Tests if the request attribute {@link ShiroHttpServletRequest}.SESSION_ID_URL_REWRITING_ENABLED is not false
     * boolean, the default behavior is to encode the URL.
     */
    @Test
    void testEncodeURLSessionIdInWhenRewriteInvalid() {

        def servletContext = mock(ServletContext)
        def httpServletResponse = mock(HttpServletResponse)
        def session = mock(HttpSession)
        def shiroHttpServletRequest = setupRequestMock()
        when(session.getId()).then(args -> URL_SESSION_ID)
        when(shiroHttpServletRequest.getSession(false)).then(args -> session)
        when(shiroHttpServletRequest.getSession()).then(args -> session)
        when(shiroHttpServletRequest.isRequestedSessionIdFromCookie()).then(args -> false)
        when(shiroHttpServletRequest.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)).then(args -> "something-else")

        def shiroHttpServletResponse = new ShiroHttpServletResponse(httpServletResponse, servletContext, shiroHttpServletRequest)

        assertEquals "/foobar;JSESSIONID=" + URL_SESSION_ID, shiroHttpServletResponse.encodeURL("/foobar")
        verify(shiroHttpServletRequest).getSession(false)
        verify(shiroHttpServletRequest).getSession()
        verify(shiroHttpServletRequest).isRequestedSessionIdFromCookie()
        verify(shiroHttpServletRequest).getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)
        verify(session, times(2)).getId()
    }

    /**
     * Tests if the request attribute {@link ShiroHttpServletRequest}.SESSION_ID_URL_REWRITING_ENABLED is null,
     * the default behavior is NOT to encode the URL.
     */
    @Test
    void testEncodeURLSessionIdInWhenRewriteInvalidAndNull() {

        def servletContext = mock(ServletContext)
        def httpServletResponse = mock(HttpServletResponse)
        def session = mock(HttpSession)
        def shiroHttpServletRequest = setupRequestMock()
        when(session.getId()).then(args -> URL_SESSION_ID)
        when(shiroHttpServletRequest.getSession(false)).then(args -> session)
        when(shiroHttpServletRequest.getSession()).then(args -> session)
        when(shiroHttpServletRequest.isRequestedSessionIdFromCookie()).then(args -> false)
        when(shiroHttpServletRequest.getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)).then(args -> null)

        def shiroHttpServletResponse = new ShiroHttpServletResponse(httpServletResponse, servletContext, shiroHttpServletRequest)

        assertEquals "/foobar;JSESSIONID=" + URL_SESSION_ID, shiroHttpServletResponse.encodeURL("/foobar")
        verify(shiroHttpServletRequest).getSession(false)
        verify(shiroHttpServletRequest).getSession()
        verify(shiroHttpServletRequest).isRequestedSessionIdFromCookie()
        verify(shiroHttpServletRequest).getAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED)
        verify(session, times(2)).getId()
    }


    private static ShiroHttpServletRequest setupRequestMock() {
        def shiroHttpServletRequest = mock(ShiroHttpServletRequest)

        when(shiroHttpServletRequest.getScheme()).then(args -> "http")
        when(shiroHttpServletRequest.getServerName()).then(args -> "localhost")
        when(shiroHttpServletRequest.getServerPort()).then(args -> 8080)
        when(shiroHttpServletRequest.getContextPath()).then(args -> "/")

        return shiroHttpServletRequest
    }

}
