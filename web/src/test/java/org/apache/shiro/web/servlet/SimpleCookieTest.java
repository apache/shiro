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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Locale;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.isA;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TODO - Class JavaDoc
 *
 * @since Apr 22, 2010 9:40:47 PM
 */
public class SimpleCookieTest {

    private SimpleCookie cookie;

    private HttpServletRequest mockRequest;
    private HttpServletResponse mockResponse;

    @BeforeEach
    public void setUp() throws Exception {
        this.mockRequest = createMock(HttpServletRequest.class);
        this.mockResponse = createMock(HttpServletResponse.class);
        this.cookie = new SimpleCookie("test");
    }

    @Test
    //Verifies fix for JSEC-94
    public void testRemoveValue() throws Exception {

        //verify that the cookie header starts with what we want
        //we can't verify the exact date format string that is appended, so we resort to just
        //simple 'startsWith' matching, which is good enough:
        String name = "test";
        String value = "deleteMe";
        String path = "/somepath";

        String headerValue = this.cookie.buildHeaderValue(name, value, null, null, path,
                0, SimpleCookie.DEFAULT_VERSION, false, false, null);

        String expectedStart = new StringBuilder()
                .append(name).append(SimpleCookie.NAME_VALUE_DELIMITER).append(value)
                .append(SimpleCookie.ATTRIBUTE_DELIMITER)
                .append(SimpleCookie.PATH_ATTRIBUTE_NAME).append(SimpleCookie.NAME_VALUE_DELIMITER).append(path)
                .toString();

        assertTrue(headerValue.startsWith(expectedStart));

        expect(mockRequest.getContextPath()).andReturn(path).times(1);
        //can't calculate the date format in the test
        mockResponse.addHeader(eq(SimpleCookie.COOKIE_HEADER_NAME), isA(String.class));
        replay(mockRequest);
        replay(mockResponse);

        this.cookie.removeFrom(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);
    }

    private void testRootContextPath(String contextPath) {
        this.cookie.setValue("blah");

        String expectedCookieValue = new StringBuilder()
                .append("test").append(SimpleCookie.NAME_VALUE_DELIMITER).append("blah")
                .append(SimpleCookie.ATTRIBUTE_DELIMITER)
                .append(SimpleCookie.PATH_ATTRIBUTE_NAME).append(SimpleCookie.NAME_VALUE_DELIMITER).append(Cookie.ROOT_PATH)
                .append(SimpleCookie.ATTRIBUTE_DELIMITER)
                .append(SimpleCookie.HTTP_ONLY_ATTRIBUTE_NAME)
                .append(SimpleCookie.ATTRIBUTE_DELIMITER)
                .append(SimpleCookie.SAME_SITE_ATTRIBUTE_NAME).append(SimpleCookie.NAME_VALUE_DELIMITER)
                .append(Cookie.SameSiteOptions.LAX.toString().toLowerCase(Locale.ENGLISH))
                .toString();

        expect(mockRequest.getContextPath()).andReturn(contextPath);
        mockResponse.addHeader(SimpleCookie.COOKIE_HEADER_NAME, expectedCookieValue);

        replay(mockRequest);
        replay(mockResponse);

        this.cookie.saveTo(mockRequest, mockResponse);

        verify(mockRequest);
        verify(mockResponse);
    }

    @Test
    /** Verifies fix for <a href="http://issues.apache.org/jira/browse/JSEC-34">JSEC-34</a> (1 of 2)*/
    public void testEmptyContextPath() throws Exception {
        testRootContextPath("");
    }


    @Test
    /** Verifies fix for <a href="http://issues.apache.org/jira/browse/JSEC-34">JSEC-34</a> (2 of 2)*/
    public void testNullContextPath() throws Exception {
        testRootContextPath(null);
    }

    @Test
    public void testReadValueInvalidPath() throws Exception {
        expect(mockRequest.getRequestURI()).andStubReturn("/foo/index.jsp");
        expect(mockRequest.getCookies()).andStubReturn(
            new jakarta.servlet.http.Cookie[] {new jakarta.servlet.http.Cookie(this.cookie.getName(), "value")});
        replay(mockRequest);
        replay(mockResponse);

        this.cookie.setPath("/bar/index.jsp");
        assertEquals(null, this.cookie.readValue(mockRequest, mockResponse));
    }

    @Test
    public void testReadValuePrefixPath() throws Exception {
        expect(mockRequest.getRequestURI()).andStubReturn("/bar/index.jsp");
        expect(mockRequest.getCookies()).andStubReturn(
            new jakarta.servlet.http.Cookie[] {new jakarta.servlet.http.Cookie(this.cookie.getName(), "value")});
        replay(mockRequest);
        replay(mockResponse);

        this.cookie.setPath("/bar");
        assertEquals("value", this.cookie.readValue(mockRequest, mockResponse));
    }

    @Test
    public void testReadValueInvalidPrefixPath() throws Exception {
        expect(mockRequest.getRequestURI()).andStubReturn("/foobar/index.jsp");
        expect(mockRequest.getCookies()).andStubReturn(
            new jakarta.servlet.http.Cookie[] {new jakarta.servlet.http.Cookie(this.cookie.getName(), "value")});
        replay(mockRequest);
        replay(mockResponse);

        this.cookie.setPath("/foo");
        assertNull(this.cookie.readValue(mockRequest, mockResponse));
    }

}
