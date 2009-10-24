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
package org.apache.shiro.web.filter.authc;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.codec.Base64;
import org.junit.Before;
import org.junit.Test;


/**
 * Test case for {@link BasicHttpAuthenticationFilter}.
 * @author Peter Ledbrook
 * @since 1.0
 */
public class BasicHttpFilterAuthenticationTest {

    BasicHttpAuthenticationFilter testFilter;

    @Before
    public void setUp() {
    }

    @Test
    public void createTokenNoAuthorizationHeader() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(null);
        expect(request.getRemoteHost()).andReturn("localhost");
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        
        replay(request);
        replay(response);
        
		AuthenticationToken token = testFilter.createToken(request, response);
		assertNotNull(token);
		assertTrue("Token is not a username and password token.", token instanceof UsernamePasswordToken);
		assertEquals("", token.getPrincipal());
		
		verify(request);
		verify(response);
    }

    @Test
    public void createTokenNoUsername() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("", ""));
        expect(request.getRemoteHost()).andReturn("localhost");
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        
        replay(request);
        replay(response);
        
		AuthenticationToken token = testFilter.createToken(request, response);
		assertNotNull(token);
		assertTrue("Token is not a username and password token.", token instanceof UsernamePasswordToken);
		assertEquals("", token.getPrincipal());
		
		verify(request);
		verify(response);
    }

    @Test
    public void createTokenNoPassword() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", ""));
        expect(request.getRemoteHost()).andReturn("localhost");
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        
        replay(request);
        replay(response);
        
		AuthenticationToken token = testFilter.createToken(request, response);
		assertNotNull(token);
		assertTrue("Token is not a username and password token.", token instanceof UsernamePasswordToken);
		
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		assertEquals("pedro", upToken.getUsername());
		assertEquals("Password is not empty.", 0, upToken.getPassword().length);
		
		verify(request);
		verify(response);
    }

    private String createAuthorizationHeader(String username, String password) {
    	return "Basic " + new String(Base64.encode((username + ":" + password).getBytes()));
    }
}
