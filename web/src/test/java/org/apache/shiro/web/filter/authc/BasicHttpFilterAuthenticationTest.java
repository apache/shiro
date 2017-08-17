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
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.Before;
import org.junit.Test;


/**
 * Test case for {@link BasicHttpAuthenticationFilter}.
 * @since 1.0
 */
public class BasicHttpFilterAuthenticationTest extends SecurityManagerTestSupport {

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

    @Test
    public void createTokenColonInPassword() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", "pass:word"));
        expect(request.getRemoteHost()).andReturn("localhost");

        HttpServletResponse response = createMock(HttpServletResponse.class);

        replay(request);
        replay(response);

		AuthenticationToken token = testFilter.createToken(request, response);
		assertNotNull(token);
		assertTrue("Token is not a username and password token.", token instanceof UsernamePasswordToken);

		UsernamePasswordToken upToken = (UsernamePasswordToken) token;
		assertEquals("pedro", upToken.getUsername());
		assertEquals("pass:word", new String(upToken.getPassword()));

		verify(request);
		verify(response);
    }
    
    @Test
    public void httpMethodDoesNotRequireAuthentication() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getMethod()).andReturn("GET");
        replay(request);
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);
        
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, new String[] { "POST", "PUT", "DELETE" });
        assertTrue("Access not allowed for GET", accessAllowed);
    }
    
    @Test
    public void httpMethodRequiresAuthentication() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", ""));
        expect(request.getRemoteHost()).andReturn("localhost");
        expect(request.getMethod()).andReturn("POST");
        replay(request);
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);
        
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, new String[] { "POST", "PUT", "DELETE" });
        assertTrue("Access allowed for POST", !accessAllowed);
    }
    
    @Test
    public void httpMethodsAreCaseInsensitive() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getMethod()).andReturn("GET");
        expect(request.getMethod()).andReturn("post");
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", "")).anyTimes();
        expect(request.getRemoteHost()).andReturn("localhost").anyTimes();
        replay(request);
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);
        
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, new String[] { "POST", "put", "delete" });
        assertTrue("Access not allowed for GET", accessAllowed);
        
        accessAllowed = testFilter.isAccessAllowed(request, response, new String[] { "post", "put", "delete" });
        assertTrue("Access allowed for POST", !accessAllowed);
    }
    
    @Test
    public void allHttpMethodsRequireAuthenticationIfNoneConfigured() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", "")).anyTimes();
        expect(request.getRemoteHost()).andReturn("localhost").anyTimes();
        expect(request.getMethod()).andReturn("GET");
        expect(request.getMethod()).andReturn("POST");
        replay(request);
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);
        
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, new String[0]);
        assertTrue("Access allowed for GET", !accessAllowed);
        
        accessAllowed = testFilter.isAccessAllowed(request, response, new String[0]);
        assertTrue("Access allowed for POST", !accessAllowed);
    }
    
    @Test
    public void allHttpMethodsRequireAuthenticationIfNullConfig() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();
        
        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", "")).anyTimes();
        expect(request.getRemoteHost()).andReturn("localhost").anyTimes();
        expect(request.getMethod()).andReturn("GET");
        expect(request.getMethod()).andReturn("POST");
        replay(request);
        
        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);
        
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, null);
        assertTrue("Access allowed for GET", !accessAllowed);
        
        accessAllowed = testFilter.isAccessAllowed(request, response, null);
        assertTrue("Access allowed for POST", !accessAllowed);
    }

    /**
     * @since 1.4
     */
    @Test
    public void permissiveEnabledWithLoginTest() {
        testFilter = new BasicHttpAuthenticationFilter();

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", "")).anyTimes();
        expect(request.getRemoteHost()).andReturn("localhost").anyTimes();
        expect(request.getMethod()).andReturn("GET");
        replay(request);

        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);

        String[] mappedValue = {"permissive"};
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, mappedValue);
        assertTrue("Access allowed for GET", !accessAllowed); // login attempt should always be false
    }

    /**
     * @since 1.4
     */
    @Test
    public void permissiveEnabledTest() {
        testFilter = new BasicHttpAuthenticationFilter();

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(null).anyTimes();
        expect(request.getRemoteHost()).andReturn("localhost").anyTimes();
        expect(request.getMethod()).andReturn("GET");
        replay(request);

        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);

        String[] mappedValue = {"permissive"};
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, mappedValue);
        assertTrue("Access should be allowed for GET", accessAllowed); // non-login attempt, return true
    }

    /**
     * @since 1.4
     */
    @Test
    public void httpMethodRequiresAuthenticationWithPermissive() throws Exception {
        testFilter = new BasicHttpAuthenticationFilter();

        HttpServletRequest request = createMock(HttpServletRequest.class);
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader("pedro", ""));
        expect(request.getRemoteHost()).andReturn("localhost");
        expect(request.getMethod()).andReturn("POST");
        replay(request);

        HttpServletResponse response = createMock(HttpServletResponse.class);
        replay(response);

        boolean accessAllowed = testFilter.isAccessAllowed(request, response, new String[] {"permissive", "POST", "PUT", "DELETE" });
        assertTrue("Access allowed for POST", !accessAllowed);
    }

    private String createAuthorizationHeader(String username, String password) {
    	return "Basic " + new String(Base64.encode((username + ":" + password).getBytes()));
    }
}
