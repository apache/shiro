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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

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

    @BeforeEach
    public void setUp() {
        request = createNiceMock(HttpServletRequest.class);
        response = createNiceMock(ServletResponse.class);
        filter = createTestInstance();
    }

    private PathMatchingFilter createTestInstance() {
        final String name = "pathMatchingFilter";

        PathMatchingFilter filter = new PathMatchingFilter() {

            @Override
            protected boolean isEnabled(ServletRequest request, ServletResponse response,
                                        String path, Object mappedValue) throws Exception {
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
        filter.setName(name);

        return filter;
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    void testDisabledBasedOnPath() throws Exception {
        filter.processPathConfig(DISABLED_PATH, null);

        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        ServletResponse response = createNiceMock(ServletResponse.class);

        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn(DISABLED_PATH).anyTimes();
        replay(request);

        boolean continueFilterChain = filter.preHandle(request, response);

        assertThat(continueFilterChain).as("FilterChain should continue.").isTrue();

        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-221">SHIRO-221<a/>.
     */
    @SuppressWarnings({"JavaDoc"})
    @Test
    void testEnabled() throws Exception {
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

        assertThat(continueFilterChain).as("FilterChain should NOT continue.").isFalse();

        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-742">SHIRO-742<a/>.
     */
    @Test
    void testPathMatchEqualUrlSeparatorEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/", request);
        assertThat(matchEnabled).as("PathMatch can match URL end with Separator").isTrue();
        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    void testPathMatchEEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/resource/book").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/resource/book").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/resource/book", request);
        assertThat(matchEnabled).as("PathMatch can match URL end with Separator").isTrue();
        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    void testPathMatchEndWithUrlSeparatorEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/resource/book/").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/resource/book/").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/resource/book", request);
        assertThat(matchEnabled).as("PathMatch can match URL end with Separator").isTrue();
        verify(request);
    }

    /**
     * Test asserting <a href="https://issues.apache.org/jira/browse/SHIRO-682">SHIRO-682<a/>.
     */
    @Test
    void testPathMatchEndWithMultiUrlSeparatorEnabled() {
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn("/resource/book//").anyTimes();
        expect(request.getServletPath()).andReturn("").anyTimes();
        expect(request.getPathInfo()).andReturn("/resource/book//").anyTimes();
        replay(request);

        boolean matchEnabled = filter.pathsMatch("/resource/book", request);
        assertThat(matchEnabled).as("PathMatch can match URL end with multi Separator").isTrue();
        verify(request);
    }


}
