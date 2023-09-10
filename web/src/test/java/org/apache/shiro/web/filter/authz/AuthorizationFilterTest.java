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

import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.test.SecurityManagerTestSupport;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Test cases for the {@link AuthorizationFilter} class.
 */
public class AuthorizationFilterTest extends SecurityManagerTestSupport {

    @Test
    public void testUserOnAccessDeniedWithResponseError() {
        // Tests when a user (known identity) is denied access and no unauthorizedUrl has been configured.
        // This should trigger an HTTP response error code.

        //log in the user using the account provided by the superclass for tests:
        runWithSubject(subject -> {
            subject.login(new UsernamePasswordToken("test", "test"));

            AuthorizationFilter filter = new AuthorizationFilter() {
                @Override
                protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
                    //for this test case
                    return false;
                }
            };

            HttpServletRequest request = mock(HttpServletRequest.class);
            HttpServletResponse response = mock(HttpServletResponse.class);

            // response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            filter.onAccessDenied(request, response);
            verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
        });
    }

    @Test
    public void testUserOnAccessDeniedWithRedirect() {
        // Tests when a user (known identity) is denied access and an unauthorizedUrl *has* been configured.
        // This should trigger an HTTP redirect

        //log in the user using the account provided by the superclass for tests:
        runWithSubject(subject -> {
            subject.login(new UsernamePasswordToken("test", "test"));

            String unauthorizedUrl = "unauthorized.jsp";

            AuthorizationFilter filter = new AuthorizationFilter() {
                @Override
                protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
                    //for this test case
                    return false;
                }
            };
            filter.setUnauthorizedUrl(unauthorizedUrl);

            HttpServletRequest request = mock(HttpServletRequest.class);
            HttpServletResponse response = mock(HttpServletResponse.class);

            String encoded = "/" + unauthorizedUrl;
            when(response.encodeRedirectURL(unauthorizedUrl)).thenReturn(encoded);
            response.sendRedirect(encoded);

            filter.onAccessDenied(request, response);

            verify(response, atLeastOnce()).sendRedirect(encoded);
            verify(response).encodeRedirectURL(unauthorizedUrl);
        });
    }
}
