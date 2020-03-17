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
package org.apache.shiro.web.util

import org.junit.Test

import javax.servlet.http.HttpServletRequest

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Tests for {@link WebUtils}.
 */
public class WebUtilsTest {

    @Test
    void testGetContextPathIncludes() {
        def request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn("/")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn("")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn("/context-path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context-path", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn("//context-path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context-path", WebUtils.getContextPath(request)
        verify request
    }

    @Test
    void testGetContextPath() {

        def request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/context-path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context-path", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("//context-path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context-path", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/context%20path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context path", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/c%6Fntext%20path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context path", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/context path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context path", WebUtils.getContextPath(request)
        verify request

        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/context%2525path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        assertEquals "/context%25path", WebUtils.getContextPath(request)
        verify request

        // non visible character's are NOT normalized, such as a backspace
        request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getContextPath()).andReturn("/context-%08path")
        expect(request.getCharacterEncoding()).andReturn("UTF-8")
        replay request
        def expected = "/context-" + (char) 0x08 + "path"
        assertEquals expected, WebUtils.getContextPath(request)
        verify request

    }

    @Test
    void testGetRequestUriWithServlet() {

        dotTestGetPathWithinApplicationFromRequest("/", "/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("", "/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("", "servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/", "servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("//", "servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("//", "//servlet", "//foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/context-path", "/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("//context-path", "//servlet", "//foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("//context-path", "/servlet", "/../servlet/other", "/servlet/other")
        dotTestGetPathWithinApplicationFromRequest("//context-path", "/asdf", "/../servlet/other", "/servlet/other")
        dotTestGetPathWithinApplicationFromRequest("//context-path", "/asdf", ";/../servlet/other", "/asdf")
        dotTestGetPathWithinApplicationFromRequest("/context%2525path", "/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/c%6Fntext%20path", "/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/context path", "/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("", null, null, "/")
        dotTestGetPathWithinApplicationFromRequest("", "index.jsp", null, "/index.jsp")
    }

    @Test
    void testGetPathWithinApplication() {

        doTestGetPathWithinApplication("/", "/foobar", "/foobar");
        doTestGetPathWithinApplication("", "/foobar", "/foobar");
        doTestGetPathWithinApplication("", "foobar", "/foobar");
        doTestGetPathWithinApplication("/", "foobar", "/foobar");
        doTestGetPathWithinApplication("//", "foobar", "/foobar");
        doTestGetPathWithinApplication("//", "//foobar", "/foobar");
        doTestGetPathWithinApplication("/context-path", "/context-path/foobar", "/foobar");
        doTestGetPathWithinApplication("/context-path", "/context-path/foobar/", "/foobar/");
        doTestGetPathWithinApplication("//context-path", "//context-path/foobar", "/foobar");
        doTestGetPathWithinApplication("//context-path", "//context-path//foobar", "/foobar");
        doTestGetPathWithinApplication("//context-path", "//context-path/remove-one/remove-two/../../././/foobar", "/foobar");
        doTestGetPathWithinApplication("//context-path", "//context-path//../../././/foobar", null);
        doTestGetPathWithinApplication("/context%2525path", "/context%2525path/foobar", "/foobar");
        doTestGetPathWithinApplication("/c%6Fntext%20path", "/c%6Fntext%20path/foobar", "/foobar");
        doTestGetPathWithinApplication("/context path", "/context path/foobar", "/foobar");

    }

    void doTestGetPathWithinApplication(String contextPath, String requestUri, String expectedValue) {

        def request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(contextPath)
        expect(request.getAttribute(WebUtils.INCLUDE_REQUEST_URI_ATTRIBUTE)).andReturn(requestUri)
        expect(request.getCharacterEncoding()).andReturn("UTF-8").times(2)
        replay request
        assertEquals expectedValue, WebUtils.getPathWithinApplication(request)
        verify request
    }

    void dotTestGetPathWithinApplicationFromRequest(String contextPath, String servletPath, String pathInfo, String expectedValue) {

        HttpServletRequest request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_CONTEXT_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getAttribute(WebUtils.INCLUDE_REQUEST_URI_ATTRIBUTE)).andReturn(null)
        expect(request.getServletPath()).andReturn(servletPath)
        expect(request.getContextPath()).andReturn(contextPath).times(2)
        expect(request.getPathInfo()).andReturn(pathInfo)
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes()
        replay request
        assertEquals expectedValue, WebUtils.getPathWithinApplication(request)
        verify request
    }
}
