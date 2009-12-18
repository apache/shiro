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

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.ExpiredSessionException;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.AbstractSessionManager;
import org.apache.shiro.subject.Subject;
import org.easymock.EasyMock;
import static org.easymock.EasyMock.*;
import org.junit.After;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Serializable;
import java.util.Map;
import java.util.UUID;

/**
 * Unit test for the {@link org.apache.shiro.web.DelegatingWebSecurityManager} implementation.
 *
 * @since 1.0
 */
public class DelegatingWebSecurityManagerTest extends AbstractWebSecurityManagerTest {

    private DelegatingWebSecurityManager sm;

    @Before
    public void setup() {
        sm = new DelegatingWebSecurityManager();
    }

    @After
    public void tearDown() {
        sm.destroy();
        super.tearDown();
    }

    protected Subject newSubject(ServletRequest request, ServletResponse response) {
        return newSubject(sm, request, response);
    }

    @Test
    public void testSessionTimeout() {

        SecurityManager delegate = createMock(SecurityManager.class);
        sm.setDelegateSecurityManager(delegate);

        HttpServletRequest mockRequest = createNiceMock(HttpServletRequest.class);
        HttpServletResponse mockResponse = createNiceMock(HttpServletResponse.class);

        expect(mockRequest.getCookies()).andReturn(null);
        expect(mockRequest.getContextPath()).andReturn("/");

        String host = "192.168.1.1";

        Serializable sessionId = UUID.randomUUID().toString();
        expect(delegate.start(EasyMock.<Map>anyObject())).andReturn(sessionId);
        expect(delegate.getHost(sessionId)).andReturn(host);
        expect(delegate.getTimeout(sessionId)).andReturn(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT);
        delegate.setTimeout(sessionId, 125L);
        expectLastCall().times(1);
        expect(delegate.getTimeout(sessionId)).andReturn(125L);
        //pretend that 125ms have gone by
        Serializable replacedSessionId = UUID.randomUUID().toString();
        @SuppressWarnings({"ThrowableInstanceNeverThrown"})
        ExpiredSessionException expired = new ExpiredSessionException("test", sessionId);
        expect(delegate.getTimeout(sessionId)).andThrow(expired);

        replay(delegate);
        replay(mockRequest);

        Subject subject = newSubject(mockRequest, mockResponse);
        Session session = subject.getSession();
        String id = session.getId().toString();
        assertEquals(AbstractSessionManager.DEFAULT_GLOBAL_SESSION_TIMEOUT, session.getTimeout());
        session.setTimeout(125);
        assertEquals(125, session.getTimeout());
        //now the underlying session should have been expired and a new one replaced by default.
        //so ensure the replaced session has the default session timeout:
        try {
            session.getTimeout();
            fail("Should have thrown an ExpiredSessionException");
        } catch (ExpiredSessionException expected) {
        }
        verify(delegate);
        verify(mockRequest);
    }
}