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
package org.apache.shiro.web.session;

import org.apache.shiro.session.mgt.SimpleSession;
import org.apache.shiro.util.ThreadContext;
import org.apache.shiro.web.WebUtils;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.ShiroHttpServletRequest;
import org.apache.shiro.web.servlet.ShiroHttpSession;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.junit.After;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertEquals;

/**
 * Test cases for the {@link DefaultWebSessionManager} implementation.
 *
 * @author Les Hazlewood
 * @since 1.0
 */
public class DefaultWebSessionManagerTest {

    @After
    public void clearThread() {
        ThreadContext.clear();
    }

    @Test
    public void testOnStart() {
        DefaultWebSessionManager mgr = new DefaultWebSessionManager();
        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);

        SimpleSession session = new SimpleSession();
        session.setId("12345");

        WebUtils.bind(createMock(HttpServletRequest.class));
        WebUtils.bind(createMock(HttpServletResponse.class));

        //test that the cookie template is being used:
        expect(cookie.getValue()).andReturn("blah");
        expect(cookie.getComment()).andReturn("comment");
        expect(cookie.getDomain()).andReturn("domain");
        expect(cookie.getMaxAge()).andReturn(SimpleCookie.DEFAULT_MAX_AGE);
        expect(cookie.getName()).andReturn(ShiroHttpSession.DEFAULT_SESSION_ID_NAME);
        expect(cookie.getPath()).andReturn("/");
        expect(cookie.getVersion()).andReturn(SimpleCookie.DEFAULT_VERSION);
        expect(cookie.isSecure()).andReturn(true);

        replay(cookie);

        mgr.onStart(session);

        verify(cookie);
    }

    @Test
    public void testOnStartWithSessionIdCookieDisabled() {

        DefaultWebSessionManager mgr = new DefaultWebSessionManager();
        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);
        mgr.setSessionIdCookieEnabled(false);

        //we should not have any reads from the cookie fields - if we do, this test case will fail.

        SimpleSession session = new SimpleSession();
        session.setId("12345");

        WebUtils.bind(createMock(HttpServletRequest.class));
        WebUtils.bind(createMock(HttpServletResponse.class));

        replay(cookie);

        mgr.onStart(session);

        verify(cookie);
    }

    @Test
    public void testGetSessionIdWithSessionIdCookieEnabled() {
        DefaultWebSessionManager mgr = new DefaultWebSessionManager();
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

        DefaultWebSessionManager mgr = new DefaultWebSessionManager();
        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);
        mgr.setSessionIdCookieEnabled(false);

        //we should not have any reads from the cookie fields - if we do, this test case will fail.

        HttpServletRequest request = createMock(HttpServletRequest.class);
        HttpServletResponse response = createMock(HttpServletResponse.class);

        String id = "12345";

        expect(request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME)).andReturn(id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);

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

        DefaultWebSessionManager mgr = new DefaultWebSessionManager();
        Cookie cookie = createMock(Cookie.class);
        mgr.setSessionIdCookie(cookie);
        mgr.setSessionIdCookieEnabled(false);

        //we should not have any reads from the cookie fields - if we do, this test case will fail.

        HttpServletRequest request = createMock(HttpServletRequest.class);
        HttpServletResponse response = createMock(HttpServletResponse.class);

        String id = "12345";

        expect(request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME)).andReturn(null);
        expect(request.getParameter(ShiroHttpSession.DEFAULT_SESSION_ID_NAME.toLowerCase())).andReturn(id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_SOURCE,
                ShiroHttpServletRequest.URL_SESSION_ID_SOURCE);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID, id);
        request.setAttribute(ShiroHttpServletRequest.REFERENCED_SESSION_ID_IS_VALID, Boolean.TRUE);

        replay(cookie);
        replay(request);
        replay(response);

        Serializable sessionId = mgr.getSessionId(request, response);
        assertEquals(sessionId, id);

        verify(cookie);
        verify(request);
        verify(response);
    }
}
