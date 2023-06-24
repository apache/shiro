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
package org.apache.shiro.web.filter.authz;

import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.easymock.EasyMock.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the {@link PortFilter} class.
 *
 * @since 1.1
 */
public class PortFilterTest {

    protected HttpServletRequest createBaseMockRequest() {
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getScheme()).andReturn("http");
        expect(request.getServerName()).andReturn("localhost");
        expect(request.getRequestURI()).andReturn("/");
        return request;
    }

    @Test
    void testDefault() throws Exception {
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);
        HttpServletRequest request = createBaseMockRequest();

        expect(response.encodeRedirectURL(eq("http://localhost/"))).andReturn("http://localhost/");
        replay(request);
        replay(response);

        PortFilter filter = new PortFilter();
        boolean result = filter.onAccessDenied(request, response, null);

        verify(request);
        verify(response);
        assertFalse(result);
    }

    /**
     * This tests the case where the client (e.g. browser) specifies a simple request to http://localhost/
     * (i.e. http scheme with the implied port of 80). The redirectURL should reflect the configured port (8080) instead
     * of the implied port 80.
     *
     * @throws Exception if there is a test failure
     */
    @Test
    void testConfiguredPort() throws Exception {
        int port = 8080;
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);
        HttpServletRequest request = createBaseMockRequest();

        String expected = "http://localhost:" + port + "/";
        expect(response.encodeRedirectURL(eq(expected))).andReturn(expected);
        replay(request);
        replay(response);

        PortFilter filter = new PortFilter();
        filter.setPort(port);
        boolean result = filter.onAccessDenied(request, response, null);

        verify(request);
        verify(response);
        assertFalse(result);
    }

}
