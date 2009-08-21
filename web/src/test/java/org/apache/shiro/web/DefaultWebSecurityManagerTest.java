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
package org.apache.shiro.web;

import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.ShiroHttpSession;
import static org.easymock.EasyMock.*;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class DefaultWebSecurityManagerTest extends AbstractWebSecurityManagerTest {

    private DefaultWebSecurityManager sm;

    @Before
    public void setup() {
        super.setup();
        sm = new DefaultWebSecurityManager();
    }

    @After
    public void tearDown() {
        super.tearDown();
        sm.destroy();
    }

    protected Subject newSubject(ServletRequest request, ServletResponse response) {
        return newSubject(sm, request, response);
    }

    @Test
    public void shiroSessionModeInit() {
        sm.setSessionMode(DefaultWebSecurityManager.NATIVE_SESSION_MODE);
    }

    protected void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void testSessionTimeout() {
        shiroSessionModeInit();
        long globalTimeout = 100;
        sm.setGlobalSessionTimeout(globalTimeout);

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        expect(mockRequest.getCookies()).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn("/");

        replay(mockRequest);

        Subject subject = newSubject(mockRequest, mockResponse);

        Session session = subject.getSession();
        Serializable origId = session.getId();
        assertEquals(session.getTimeout(), globalTimeout);
        session.setTimeout(125);
        assertEquals(session.getTimeout(), 125);
        sleep(200);
        try {
            session.getTimeout();
            fail("Session should have expired.");
        } catch (ExpiredSessionException expected) {
        }
    }

    @Test
    public void testGetSubjectByRequestResponsePair() {
        shiroSessionModeInit();

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        expect(mockRequest.getCookies()).andReturn(null);

        replay(mockRequest);
        replay(mockResponse);

        Subject subject = newSubject(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);

        assertNotNull(subject);
        assertTrue(subject.getPrincipals() == null || subject.getPrincipals().isEmpty());
        assertTrue(subject.getSession(false) == null);
        assertFalse(subject.isAuthenticated());
    }

    @Test
    public void testGetSubjectByRequestSessionId() {

        shiroSessionModeInit();

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        replay(mockRequest);
        replay(mockResponse);

        Subject subject = newSubject(mockRequest, mockResponse);

        Session session = subject.getSession();
        Serializable sessionId = session.getId();

        assertNotNull(sessionId);

        verify(mockRequest);
        verify(mockResponse);

        mockRequest = createNiceMock(HttpServletRequest.class);
        WebUtils.bind(mockRequest);
        mockResponse = createNiceMock(HttpServletResponse.class);
        WebUtils.bind(mockResponse);
        //now simulate the cookie going with the request and the Subject should be acquired based on that:
        Cookie[] cookies = new Cookie[]{new Cookie(ShiroHttpSession.DEFAULT_SESSION_ID_NAME, sessionId.toString())};
        expect(mockRequest.getCookies()).andReturn(cookies).anyTimes();
        expect(mockRequest.getParameter(isA(String.class))).andReturn(null).anyTimes();

        replay(mockRequest);
        replay(mockResponse);

        subject = newSubject(mockRequest, mockResponse);

        session = subject.getSession(false);
        assertNotNull(session);
        assertEquals(sessionId, session.getId());

        verify(mockRequest);
        verify(mockResponse);
    }

}
