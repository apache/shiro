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
package org.apache.shiro.web.filter.authc

import org.apache.shiro.authc.AuthenticationToken
import org.apache.shiro.authc.BearerToken
import org.apache.shiro.test.SecurityManagerTestSupport
import org.hamcrest.CoreMatchers
import org.hamcrest.Matchers
import org.junit.jupiter.api.Test

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import static org.easymock.EasyMock.*
import static org.hamcrest.MatcherAssert.assertThat

/**
 * Test case for {@link BearerHttpAuthenticationFilter}.
 * @since 1.5
 */
class BearerHttpFilterAuthenticationTest extends SecurityManagerTestSupport {

    @Test
    void createTokenNoAuthorizationHeader() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = mockRequest()
        HttpServletResponse response = mockResponse()
        
        AuthenticationToken token = testFilter.createToken(request, response)
        assertThat(token, CoreMatchers.instanceOf(BearerToken.class))
        assertThat(token.getPrincipal(), Matchers.is(""))

        verify(request, response)
    }

    @Test
    void createTokenNoValue() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = mockRequest("")
        HttpServletResponse response = mockResponse()
        
        AuthenticationToken token = testFilter.createToken(request, response)
        assertThat(token, CoreMatchers.instanceOf(BearerToken.class))
        assertThat(token.getPrincipal(), Matchers.is(""))

        verify(request, response)
    }

    @Test
    void createTokenWithValue() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = mockRequest("some-value")
        HttpServletResponse response = mockResponse()

        AuthenticationToken token = testFilter.createToken(request, response)
        assertThat(token, CoreMatchers.instanceOf(BearerToken.class))
        assertThat(token.getPrincipal(), Matchers.is("some-value"))

        verify(request, response)
    }

    @Test
    void createTokenJustSpaces() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = mockRequest("  ")
        HttpServletResponse response = mockResponse()

        AuthenticationToken token = testFilter.createToken(request, response)
        assertThat(token, CoreMatchers.instanceOf(BearerToken.class))
        assertThat(token.getPrincipal(), Matchers.is(""))

        verify(request, response)
    }
    
    @Test
    void httpMethodDoesNotRequireAuthentication() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()
        
        HttpServletRequest request = createMock(HttpServletRequest.class)
        expect(request.getMethod()).andReturn("GET")
        replay(request)
        
        HttpServletResponse response = createMock(HttpServletResponse.class)
        replay(response)

        String[] methods =  [ "POST", "PUT", "DELETE" ]
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, methods)
        assertThat("Access not allowed for GET", accessAllowed)
        verify(request, response)
    }
    
    @Test
    void httpMethodRequiresAuthentication() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()
        
        HttpServletRequest request = mockRequest("valid-token", "localhost", {
            expect(it.getMethod()).andReturn("POST")
        })
        
        HttpServletResponse response = mockResponse()

        String[] methods =  [ "POST", "PUT", "DELETE" ]
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, methods)
        assertThat("Access allowed for POST", !accessAllowed)
    }

    @Test
    void permissiveEnabledWithLoginTest() {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = mockRequest("valid-token", "localhost", {
            expect(it.getMethod()).andReturn("GET")
        })

        HttpServletResponse response = mockResponse()

        String[] mappedValue = ["permissive"]
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, mappedValue)
        assertThat("Access allowed for GET", !accessAllowed) // login attempt should always be false
    }

    @Test
    void permissiveEnabledTest() {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = createMock(HttpServletRequest.class)
        expect(request.getHeader("Authorization")).andReturn(null)
        expect(request.getMethod()).andReturn("GET")
        expect(request.getRemoteHost()).andReturn("localhost")
        replay(request)

        HttpServletResponse response = mockResponse()

        String[] mappedValue = ["permissive"]
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, mappedValue)
        assertThat("Access should be allowed for GET", accessAllowed) // non-login attempt, return true
    }

    @Test
    void httpMethodRequiresAuthenticationWithPermissive() throws Exception {
        BearerHttpAuthenticationFilter testFilter = new BearerHttpAuthenticationFilter()

        HttpServletRequest request = mockRequest("a-valid-token", "localhost", {
            expect(it.getMethod()).andReturn("POST")
        })

        HttpServletResponse response = mockResponse()

        String[] mappedValue = ["permissive", "POST", "PUT", "DELETE" ]
        boolean accessAllowed = testFilter.isAccessAllowed(request, response, mappedValue)
        assertThat("Access allowed for POST", !accessAllowed)
    }

    static private String createAuthorizationHeader(String token) {
        return "Bearer " + token
    }

    static HttpServletRequest mockRequest() {

        HttpServletRequest request = createMock(HttpServletRequest.class)
        expect(request.getHeader("Authorization")).andReturn(null)
        expect(request.getRemoteHost()).andReturn("localhost")

        replay(request)
        return request
    }

    static HttpServletRequest mockRequest(String token, String host = "localhost", Closure<HttpServletRequest> additionalMockConfig = null) {

        HttpServletRequest request = createMock(HttpServletRequest.class)
        expect(request.getHeader("Authorization")).andReturn(createAuthorizationHeader(token))
        expect(request.getRemoteHost()).andReturn(host)

        if (additionalMockConfig != null) {
            additionalMockConfig.call(request)
        }

        replay(request)
        return request
    }

    static HttpServletResponse mockResponse() {

        HttpServletResponse response = createMock(HttpServletResponse.class)
        replay(response)
        return response
    }
}
