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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.easymock.EasyMock.*;

/**
 * Test cases for the {@link AuthorizationFilter} class.
 */
public class AuthorizationFilterTest extends SecurityManagerTestSupport {

    @Test
    public void testUserOnAccessDeniedWithResponseError() throws IOException {
        // Tests when a user (known identity) is denied access and no unauthorizedUrl has been configured.
        // This should trigger an HTTP response error code.

        //log in the user using the account provided by the superclass for tests:
        SecurityUtils.getSubject().login(new UsernamePasswordToken("test", "test"));
        
        AuthorizationFilter filter = new AuthorizationFilter() {
            @Override
            protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
                    throws Exception {
                return false; //for this test case
            }
        };

        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        replay(response);
        filter.onAccessDenied(request, response);
        verify(response);
    }

    @Test
    public void testUserOnAccessDeniedWithRedirect() throws IOException {
        // Tests when a user (known identity) is denied access and an unauthorizedUrl *has* been configured.
        // This should trigger an HTTP redirect

        //log in the user using the account provided by the superclass for tests:
        SecurityUtils.getSubject().login(new UsernamePasswordToken("test", "test"));

        String unauthorizedUrl = "unauthorized.jsp";

        AuthorizationFilter filter = new AuthorizationFilter() {
            @Override
            protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue)
                    throws Exception {
                return false; //for this test case
            }
        };
        filter.setUnauthorizedUrl(unauthorizedUrl);

        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        HttpServletResponse response = createNiceMock(HttpServletResponse.class);

        expect(request.getContextPath()).andReturn("/").anyTimes();

        String encoded = "/" + unauthorizedUrl;
        expect(response.encodeRedirectURL(unauthorizedUrl)).andReturn(encoded);
        response.sendRedirect(encoded);
        replay(request);
        replay(response);

        filter.onAccessDenied(request, response);

        verify(request);
        verify(response);
    }
}
