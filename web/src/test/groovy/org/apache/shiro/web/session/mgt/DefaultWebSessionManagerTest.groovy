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

import org.apache.shiro.session.mgt.SimpleSession
import org.apache.shiro.util.ThreadContext
import org.apache.shiro.web.servlet.Cookie
import org.apache.shiro.web.servlet.ShiroHttpServletRequest
import org.apache.shiro.web.servlet.ShiroHttpSession
import org.apache.shiro.web.servlet.SimpleCookie
import org.junit.After
import org.junit.Before
import org.junit.Test

import javax.servlet.ServletRequest
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import static org.easymock.EasyMock.*
import static org.junit.Assert.assertEquals
import static org.junit.Assert.assertNull

/**
 * Test cases for the {@link DefaultWebSessionManager} implementation.
 *
 * @since 1.0
 */
public class DefaultWebSessionManagerTest {


    DefaultWebSessionManager mgr;

    @Before
    void setUp() {
        this.mgr = new DefaultWebSessionManager()
    }

    @After
    public void clearThread() {
        ThreadContext.remove();
    }

    @Test
    public void testOnStart() {
        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);

        SimpleSession session = new SimpleSession();
        session.setId("12345");

        WebSessionContext wsc = new DefaultWebSessionContext();
        wsc.setServletRequest(createMock(HttpServletRequest.class));
        wsc.setServletResponse(createMock(HttpServletResponse.class));

        //test that the cookie template is being used:
        expect(cookie.getValue()).andReturn("blah");
        expect(cookie.getComment()).andReturn("comment");
        expect(cookie.getDomain()).andReturn("domain");
        expect(cookie.getMaxAge()).andReturn(SimpleCookie.DEFAULT_MAX_AGE);
        expect(cookie.getName()).andReturn(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        expect(cookie.getPath()).andReturn("/");
        expect(cookie.getVersion()).andReturn(SimpleCookie.DEFAULT_VERSION);
        expect(cookie.isSecure()).andReturn(true);
        expect(cookie.isHttpOnly()).andReturn(true);
        expect(cookie.getSameSite()).andReturn(Cookie.SameSiteOptions.LAX);

        replay(cookie);

        mgr.onStart(session, wsc);

        verify(cookie);
    }

    @Test
    public void testOnStartWithSessionIdCookieDisabled() {

        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);
        mgr.setSessionIdCookieEnabled(false);

        //we should not have any reads from the cookie fields - if we do, this test case will fail.

        SimpleSession session = new SimpleSession();
        session.setId("12345");

        WebSessionContext wsc = new DefaultWebSessionContext();
        wsc.setServletRequest(createMock(HttpServletRequest.class));
        wsc.setServletResponse(createMock(HttpServletResponse.class));

        replay(cookie);

        mgr.onStart(session, wsc);

        verify(cookie);
    }

    @Test
    public void testGetSessionIdWithSessionIdCookieEnabled() {
        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);

        HttpServletRequest request = createMock(HttpServletRequest.class);
        HttpServletResponse response = createMock(HttpServletResponse.class);

        String id = "12345";

        expect(cookie.readValue(request, response)).andReturn(id);

        //expect that state attributes are set correctly
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                ShiroHttpServletRequest.COOKIE_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        request.setAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED, Boolean.FALSE);

        replay(cookie);
        replay(request);
        replay(response);

        Serializable sessionId = mgr.getSessionId(request, response);
        assertEquals(sessionId, id);

        verify(cookie);
        verify(request);
        verify(response);
    }

    @Test
    public void testGetSessionIdWithSessionIdCookieDisabled() {

        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);
        mgr.setSessionIdCookieEnabled(false);
        mgr.setSessionIdUrlRewritingEnabled(true)

        //we should not have any reads from the cookie fields - if we do, this test case will fail.

        HttpServletRequest request = createMock(HttpServletRequest.class);
        HttpServletResponse response = createMock(HttpServletResponse.class);

        String id = "12345";

        expect(cookie.getName()).andReturn(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        expect(request.getRequestURI()).andReturn("/foo/bar?JSESSIONID=$id" as String)
        expect(request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME)).andReturn(id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        request.setAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED, Boolean.TRUE);

        replay(cookie);
        replay(request);
        replay(response);

        Serializable sessionId = mgr.getSessionId(request, response);
        assertEquals(sessionId, id);

        verify(cookie);
        verify(request);
        verify(response);
    }

    @Test
    public void testGetSessionIdWithSessionIdCookieDisabledAndLowercaseRequestParam() {

        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);
        mgr.setSessionIdCookieEnabled(false);
        mgr.setSessionIdUrlRewritingEnabled(true)

        //we should not have any reads from the cookie fields - if we do, this test case will fail.

        HttpServletRequest request = createMock(HttpServletRequest.class);
        HttpServletResponse response = createMock(HttpServletResponse.class);

        String id = "12345";

        expect(cookie.getName()).andReturn(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        expect(request.getRequestURI()).andReturn("/foo/bar?JSESSIONID=$id" as String)
        expect(request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME)).andReturn(null);
        expect(request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME.toLowerCase())).andReturn(id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        request.setAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED, Boolean.TRUE);

        replay(cookie);
        replay(request);
        replay(response);

        Serializable sessionId = mgr.getSessionId(request, response);
        assertEquals(sessionId, id);

        verify(cookie);
        verify(request);
        verify(response);
    }

    //SHIRO-351:
    //since 1.2.2
    @Test
    public void testGetSessionIdFromRequestUriPathSegmentParam() {

        mgr.setSessionIdCookieEnabled(false);
        mgr.setSessionIdUrlRewritingEnabled(true)

        HttpServletRequest request = createMock(HttpServletRequest.class);
        HttpServletResponse response = createMock(HttpServletResponse.class);

        String id = "12345";

        expect(request.getRequestURI()).andReturn("/foo/bar.html;JSESSIONID=$id;key2=value2?key3=value3" as String)

        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE, ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);
        request.setAttribute(ShiroHttpServletRequest.SESSION_ID_URL_REWRITING_ENABLED, Boolean.TRUE);

        replay(request);
        replay(response);

        Serializable sessionId = mgr.getSessionId(request, response);
        assertEquals(sessionId, id);

        verify(request);
        verify(response);
    }

    //SHIRO-351:
    //since 1.2.2
    @Test
    void testSessionIDRequestPathParameterWithNonHttpRequest() {

        def request = createMock(ServletRequest)

        replay request

        assertNull mgr.getUriPathSegmentParamValue(request, ShiroHttpSession.DEFAULT_SESSION_ID_NAME)

        verify request
    }

    //SHIRO-351:
    //since 1.2.2
    @Test
    void testSessionIDRequestPathParameterWithoutARequestURI() {

        def request = createMock(HttpServletRequest)

        expect(request.getRequestURI()).andReturn null
        replay request

        assertNull mgr.getUriPathSegmentParamValue(request, ShiroHttpSession.DEFAULT_SESSION_ID_NAME)

        verify request
    }

    //SHIRO-351:
    //since 1.2.2
    @Test
    void testSessionIDRequestPathParameterWithoutPathParameters() {

        def request = createMock(HttpServletRequest)

        expect(request.getRequestURI()).andReturn '/foo/bar/baz.html'
        replay request

        assertNull mgr.getUriPathSegmentParamValue(request, ShiroHttpSession.DEFAULT_SESSION_ID_NAME)

        verify request
    }

    //SHIRO-351:
    //since 1.2.2
    @Test
    void testSessionIDRequestPathParameterWithoutJSESSIONID() {

        def request = createMock(HttpServletRequest)

        expect(request.getRequestURI()).andReturn '/foo/bar;key1=key2;a/b/c;blah'
        replay request

        assertNull mgr.getUriPathSegmentParamValue(request, ShiroHttpSession.DEFAULT_SESSION_ID_NAME)

        verify request
    }

    //SHIRO-351:
    //since 1.2.2
    @Test
    void testSessionIDRequestPathParameter() {

        def request = createMock(HttpServletRequest)

        def id = 'baz'
        def path = "/foo/bar;key1=value1;key3,key4,key5;JSESSIONID=$id;key6=value6?key7=value7&key8=value8"

        expect(request.getRequestURI()).andReturn(path.toString())
        replay request

        String found = mgr.getUriPathSegmentParamValue(request, ShiroHttpSession.DEFAULT_SESSION_ID_NAME)

        assertEquals id, found

        verify request
    }
}
