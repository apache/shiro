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
package org.apache.shiro.web.servlet;

import static org.easymock.EasyMock.*;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.Before;
import org.junit.Test;

import junit.framework.TestCase;

public class ShiroHttpServletRequestTest extends TestCase {

	private ShiroHttpServletRequest request;
	
	private HttpServletRequest mockRequest;
    private ServletContext mockContext;
    private Subject mockSubject;
	
    @Before
    public void setUp() throws Exception {
    	this.mockRequest = createMock(HttpServletRequest.class);
    	this.mockContext = createMock(ServletContext.class);
    	this.mockSubject = createMock(Subject.class);
    	
    	ThreadContext.bind(this.mockSubject);
    	this.request = new ShiroHttpServletRequest(mockRequest, mockContext, false);
    }
    
    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-637">SHIRO-637<a/>.
     */
    @Test
    public void testRegetSession() throws Exception {
        Session session1 = createMock(Session.class);
        Session session2 = createMock(Session.class);
    	
        mockSubject.logout();
        expect(mockSubject.getSession(true))
           .andReturn(session1).times(1)
           .andReturn(session2).times(1);
        expect(mockSubject.getSession(false))
            .andReturn(session1).times(2)
            .andReturn(null).times(3);
        replay(mockSubject);
        
        assertNotNull(request.getSession(true));
        assertNotNull(request.getSession(false));
        
        mockSubject.logout();
        
        assertNull(request.getSession(false));
        assertNotNull(request.getSession(true));
        verify(mockSubject);
    }
}
