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
package org.jsecurity.web.attr;

import junit.framework.TestCase;
import static org.easymock.EasyMock.*;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Les Hazlewood
 * @since 0.9
 */
public class CookieAttributeTest extends TestCase {

    private CookieAttribute<String> cookieAttribute;
    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;

    @Before
    public void setUp() throws Exception {
        this.mockRequest = createMock(HttpServletRequest.class);
        this.mockResponse = createMock(HttpServletResponse.class);
        this.cookieAttribute = new CookieAttribute<String>("test");
    }

    @Test
    //Verifies fix for JSEC-94
    public void testRemoveValue() throws Exception {

        Cookie cookie = new Cookie("test", "blah");
        cookie.setMaxAge(2351234); //doesn't matter what the time is
        Cookie[] cookies = new Cookie[]{cookie};

        expect(mockRequest.getCookies()).andReturn(cookies);
        //no path set on the cookie, so we expect to retrieve it from the context path
        expect(mockRequest.getContextPath()).andReturn("/somepath");
        mockResponse.addCookie(cookie);
        replay(mockRequest);
        replay(mockResponse);

        cookieAttribute.removeValue(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);

        assertTrue(cookie.getMaxAge() == 0);
        assertTrue(cookie.getPath().equals("/somepath"));
    }
}
