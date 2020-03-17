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
package org.apache.shiro.web.filter;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the {@link PathMatchingFilter} implementation.
 */
public class PathMatchingFilterTest {

    private static final String CONTEXT_PATH = "/";
    private static final String ENABLED_PATH = CONTEXT_PATH + "enabled";
    private static final String DISABLED_PATH = CONTEXT_PATH + "disabled";

    HttpServletRequest request;
    ServletResponse response;
    PathMatchingFilter filter;

    @Before
    public void setUp() {
        request = createNiceMock(HttpServletRequest.class);
        response = createNiceMock(ServletResponse.class);
        filter = createTestInstance();
    }

    private PathMatchingFilter createTestInstance() {
        final String NAME = "pathMatchingFilter";

        PathMatchingFilter filter = new PathMatchingFilter() {
            @Override
            protected boolean isEnabled(ServletRequest request, ServletResponse response, String path, Object mappedValue) throws Exception {
                return !path.equals(DISABLED_PATH);
            }

            @Override
            protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
                //simulate a subclass that handles the response itself (A 'false' return value indicates that the
                //FilterChain should not continue to be executed)
                //
                //This method should only be called if the filter is enabled, so we know if the return value is
                //false, then the filter was enabled.  A true return value from 'onPreHandle' indicates this test
                //filter was disabled or a path wasn't matched.
                return false;
            }
        };
        filter.setName(NAME);

        return filter;
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    public void testDisabledBasedOnPath() throws Exception {
        filter.processPathConfig(DISABLED_PATH, null);

        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        ServletResponse response = createNiceMock(ServletResponse.class);

        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn(DISABLED_PATH).anyTimes();
        replay(request);

        boolean continueFilterChain = filter.preHandle(request, response);

        assertTrue("FilterChain should continue.", continueFilterChain);

        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    public void testEnabled() throws Exception {
        //Configure the filter to reflect 2 configured paths.  This test will simulate a request to the
        //enabled path
        filter.processPathConfig(DISABLED_PATH, null);
        filter.processPathConfig(ENABLED_PATH, null);

        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        ServletResponse response = createNiceMock(ServletResponse.class);

        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn(ENABLED_PATH).anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn(ENABLED_PATH).anyTimes();
        replay(request);

        boolean continueFilterChain = filter.preHandle(request, response);

        assertFalse("FilterChain should NOT continue.", continueFilterChain);

        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-742">SHIRO-742<a/>.
     */
    @Test
    public void testPathMatchEqualUrlSeparatorEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/", request);
        assertTrue("PathMatch can match URL end with Separator", matchEnabled);
        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    public void testPathMatchEEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/resource/book").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/resource/book").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/resource/book", request);
        assertTrue("PathMatch can match URL end with Separator", matchEnabled);
        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    public void testPathMatchEndWithUrlSeparatorEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/resource/book/").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/resource/book/").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/resource/book", request);
        assertTrue("PathMatch can match URL end with Separator", matchEnabled);
        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    public void testPathMatchEndWithMultiUrlSeparatorEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/resource/book//").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/resource/book//").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/resource/book", request);
        assertTrue("PathMatch can match URL end with multi Separator", matchEnabled);
        verify(request);
    }


}
