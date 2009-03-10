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
package org.ki.web.attr;

import junit.framework.TestCase;
import static org.easymock.EasyMock.*;
import org.easymock.IArgumentMatcher;
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
        expect(mockRequest.getContextPath()).andReturn("/somepath").times(2);
        mockResponse.addCookie(cookie);
        replay(mockRequest);
        replay(mockResponse);

        cookieAttribute.removeValue(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);

        assertTrue(cookie.getMaxAge() == 0);
        assertTrue(cookie.getPath().equals("/somepath"));
    }

    private void testContextPath(String contextPath) {
        Cookie cookie = new Cookie("test", "blah");
        cookie.setMaxAge(-1);
        cookie.setPath("/");

        expect(mockRequest.getContextPath()).andReturn(contextPath);

        mockResponse.addCookie(eqCookie(cookie));

        replay(mockRequest);
        replay(mockResponse);

        cookieAttribute.setName("test");
        cookieAttribute.storeValue("blah", mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);
    }

    @Test
    /** Verifies fix for <a href="http://issues.apache.org/jira/browse/JSEC-34">JSEC-34</a> (1 of 2)*/
    public void testEmptyContextPath() throws Exception {
        testContextPath("");
    }


    @Test
    /** Verifies fix for <a href="http://issues.apache.org/jira/browse/JSEC-34">JSEC-34</a> (2 of 2)*/
    public void testNullContextPath() throws Exception {
        testContextPath(null);
    }

    private static <T extends Cookie> T eqCookie(final T in) {
        reportMatcher(new IArgumentMatcher() {
            public boolean matches(Object o) {
                Cookie c = (Cookie) o;
                return c.getName().equals(in.getName()) &&
                        c.getPath().equals(in.getPath()) &&
                        c.getMaxAge() == in.getMaxAge() &&
                        c.getSecure() == in.getSecure() &&
                        c.getValue().equals(in.getValue());
            }

            public void appendTo(StringBuffer sb) {
                sb.append("eqCookie(");
                sb.append(in.getClass().getName());
                sb.append(")");

            }
        });
        return null;
    }

    @Test
    //Verifies fix for JSEC-64
    public void testRemoveValueWithNullContext() throws Exception {

        Cookie cookie = new Cookie("test", "blah");
        cookie.setMaxAge(2351234); //doesn't matter what the time is
        Cookie[] cookies = new Cookie[]{cookie};

        expect(mockRequest.getCookies()).andReturn(cookies);
        //no path set on the cookie, so we expect to retrieve it from the context path
        expect(mockRequest.getContextPath()).andReturn(null).times(2);
        mockResponse.addCookie(cookie);
        replay(mockRequest);
        replay(mockResponse);

        cookieAttribute.removeValue(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);

        assertTrue(cookie.getMaxAge() == 0);
        assertTrue(cookie.getPath().equals("/"));
    }

}
