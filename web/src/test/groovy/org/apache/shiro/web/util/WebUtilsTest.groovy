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

import org.apache.shiro.web.RestoreSystemProperties
import org.hamcrest.CoreMatchers
import org.junit.Test

import javax.servlet.http.HttpServletRequest

import static org.easymock.EasyMock.*
import static org.junit.Assert.*
import static org.hamcrest.CoreMatchers.*

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

        dotTestGetPathWithinApplicationFromRequest("/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("//servlet", "//foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("//servlet", "//foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/servlet", "/../servlet/other", "/servlet/other")
        dotTestGetPathWithinApplicationFromRequest("/asdf", "/../servlet/other", "/servlet/other")
        dotTestGetPathWithinApplicationFromRequest("/asdf/foo", ";/../servlet/other", "/asdf/foo")
        dotTestGetPathWithinApplicationFromRequest("/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest("/servlet", "/foobar", "/servlet/foobar")
        dotTestGetPathWithinApplicationFromRequest(null, null, "/")
        dotTestGetPathWithinApplicationFromRequest("index.jsp", null, "/index.jsp")
    }

    @Test
    void testGetPathWithinApplication() {

        doTestGetPathWithinApplication("/foobar", null, "/foobar");
        doTestGetPathWithinApplication("/foobar", "", "/foobar");
        doTestGetPathWithinApplication("", "/", "/");
        doTestGetPathWithinApplication("", null, "/");
        doTestGetPathWithinApplication("/foobar", "//", "/foobar/");
        doTestGetPathWithinApplication("/foobar", "//extra", "/foobar/extra");
        doTestGetPathWithinApplication("/foobar", "//extra///", "/foobar/extra/");
        doTestGetPathWithinApplication("/foo bar", "/path info" ,"/foo bar/path info");
    }

    @Test
    void testGetRequestURI() {
        doTestGetRequestURI("/foobar", "/foobar")
        doTestGetRequestURI( "/foobar/", "/foobar/")
        doTestGetRequestURI("",  "/");
        doTestGetRequestURI("foobar", "/foobar");
        doTestGetRequestURI("//foobar", "/foobar");
        doTestGetRequestURI("//foobar///", "/foobar/");
        doTestGetRequestURI("/context-path/foobar", "/context-path/foobar");
        doTestGetRequestURI("/context-path/foobar/", "/context-path/foobar/");
        doTestGetRequestURI("//context-path/foobar", "/context-path/foobar");
        doTestGetRequestURI("//context-path//foobar", "/context-path/foobar");
        doTestGetRequestURI("//context-path/remove-one/remove-two/../../././/foobar", "/context-path/foobar");
        doTestGetRequestURI("//context-path//../../././/foobar", null);
        doTestGetRequestURI("/context%2525path/foobar", "/context%25path/foobar");
        doTestGetRequestURI("/c%6Fntext%20path/foobar", "/context path/foobar");
        doTestGetRequestURI("/context path/foobar", "/context path/foobar");
    }

    @Test
    void testNormalize() {
        doNormalizeTest"/foobar", "/foobar"
        doNormalizeTest "/foobar/", "/foobar/"
        doNormalizeTest"", "/"
        doNormalizeTest"foobar", "/foobar"
        doNormalizeTest"//foobar", "/foobar"
        doNormalizeTest"//foobar///", "/foobar/"
        doNormalizeTest"/context-path/foobar", "/context-path/foobar"
        doNormalizeTest"/context-path/foobar/", "/context-path/foobar/"
        doNormalizeTest"//context-path/foobar", "/context-path/foobar"
        doNormalizeTest"//context-path//foobar" ,"/context-path/foobar"
        doNormalizeTest"//context-path/remove-one/remove-two/../../././/foobar", "/context-path/foobar"
        doNormalizeTest"//context-path//../../././/foobar", null
        doNormalizeTest"/context path/foobar", "/context path/foobar"

        doNormalizeTest"/context path/\\foobar", "/context path/\\foobar"
        doNormalizeTest"//context-path\\..\\../.\\.\\foobar", "/context-path\\..\\../.\\.\\foobar"
        doNormalizeTest"//context-path\\..\\..\\.\\.\\foobar", "/context-path\\..\\..\\.\\.\\foobar"
        doNormalizeTest"\\context-path\\..\\foobar", "/\\context-path\\..\\foobar"
    }

    @Test
    void testNormalize_allowBackslashes() {
        RestoreSystemProperties.withProperties(["org.apache.shiro.web.ALLOW_BACKSLASH": "true"]) {
            doNormalizeTest"/foobar", "/foobar"
            doNormalizeTest "/foobar/", "/foobar/"
            doNormalizeTest"", "/"
            doNormalizeTest"foobar", "/foobar"
            doNormalizeTest"//foobar", "/foobar"
            doNormalizeTest"//foobar///", "/foobar/"
            doNormalizeTest"/context-path/foobar", "/context-path/foobar"
            doNormalizeTest"/context-path/foobar/", "/context-path/foobar/"
            doNormalizeTest"//context-path/foobar", "/context-path/foobar"
            doNormalizeTest"//context-path//foobar" ,"/context-path/foobar"
            doNormalizeTest"//context-path/remove-one/remove-two/../../././/foobar", "/context-path/foobar"
            doNormalizeTest"//context-path//../../././/foobar", null
            doNormalizeTest"/context path/foobar", "/context path/foobar"
            doNormalizeTest"/context path/\\foobar", "/context path/foobar"
            doNormalizeTest"//context-path\\..\\..\\.\\.\\foobar", null
            doNormalizeTest"\\context-path\\..\\foobar", "/foobar"

        }
    }

    void doNormalizeTest(String path, String expected) {
        assertThat WebUtils.normalize(path), equalTo(expected)
    }

    void doTestGetPathWithinApplication(String servletPath, String pathInfo, String expectedValue) {

        def request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE)).andReturn(servletPath)
        expect(request.getAttribute(WebUtils.INCLUDE_PATH_INFO_ATTRIBUTE)).andReturn(pathInfo)
        if (pathInfo == null) {
            expect(request.getPathInfo()).andReturn(null) // path info can be null
        }
        replay request
        assertEquals expectedValue, WebUtils.getPathWithinApplication(request)
        verify request
    }

    void doTestGetRequestURI(String rawRequestUri, String expectedValue) {

        def request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_REQUEST_URI_ATTRIBUTE)).andReturn(rawRequestUri)
        expect(request.getCharacterEncoding()).andReturn("UTF-8").times(1)
        replay request
        assertEquals expectedValue, WebUtils.getRequestUri(request)
        verify request
    }

    void dotTestGetPathWithinApplicationFromRequest(String servletPath, String pathInfo, String expectedValue) {

        HttpServletRequest request = createMock(HttpServletRequest)
        expect(request.getAttribute(WebUtils.INCLUDE_SERVLET_PATH_ATTRIBUTE)).andReturn(null)
        expect(request.getAttribute(WebUtils.INCLUDE_PATH_INFO_ATTRIBUTE)).andReturn(null)
        expect(request.getServletPath()).andReturn(servletPath)
        expect(request.getPathInfo()).andReturn(pathInfo)
        expect(request.getCharacterEncoding()).andReturn("UTF-8").anyTimes()
        replay request
        assertEquals expectedValue, WebUtils.getPathWithinApplication(request)
        verify request
    }
}
