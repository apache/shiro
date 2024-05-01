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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.easymock.EasyMock.createNiceMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;

/**
 * Unit tests for the {@link PathMatchingFilter} implementation.
 */
public class PathMatchingFilterParameterizedTest {

    private static final Logger LOG = LoggerFactory.getLogger(PathMatchingFilterParameterizedTest.class);

    private static final String CONTEXT_PATH = "/";
    private static final String DISABLED_PATH = CONTEXT_PATH + "disabled";

    private String pattern;
    private HttpServletRequest request;
    private boolean shouldMatch;
    private PathMatchingFilter filter;

    /**
     * Tests the following assumptions:
     *
     * <pre>
     * URL                 Must match pattern      Must not match pattern
     * /foo/               /foo/*                  /foo* || /foo
     * /foo/bar            /foo/*                  /foo* || /foo
     * /foo                /foo                    /foo/*
     * </pre>
     */
    public static Object[][] generateParameters() {

        return Stream.of(
                        new Object[] {"/foo/*", createRequest("/foo/"), true},
                        new Object[] {"/foo*", createRequest("/foo/"), true},
                        new Object[] {"/foo", createRequest("/foo/"), true},

                        new Object[] {"/foo/*", createRequest("/foo/bar"), true},
                        new Object[] {"/foo*", createRequest("/foo/bar"), false},
                        new Object[] {"/foo", createRequest("/foo/bar"), false},

                        new Object[] {"/foo", createRequest("/foo"), true},
                        new Object[] {"/foo/*", createRequest("/foo"), false},
                        new Object[] {"/foo/*", createRequest("/foo "), false},
                        new Object[] {"/foo/*", createRequest("/foo /"), false},
                        // already URL decoded, encoded would have been %2520
                        new Object[] {"/foo/*", createRequest("/foo%20"), false},
                        new Object[] {"/foo/*", createRequest("/foo%20/"), false},
                        new Object[] {"/foo/*", createRequest("/foo/%20/"), true},
                        new Object[] {"/foo/*", createRequest("/foo/ /"), true}
                )
                .toArray(Object[][]::new);
    }

    public static HttpServletRequest createRequest(String requestUri) {
        return createRequest(requestUri, "", requestUri);
    }

    public static HttpServletRequest createRequest(String requestUri, String servletPath, String pathInfo) {
        HttpServletRequest request = createNiceMock(HttpServletRequest.class);
        expect(request.getContextPath()).andReturn(CONTEXT_PATH).anyTimes();
        expect(request.getRequestURI()).andReturn(requestUri).anyTimes();
        expect(request.getServletPath()).andReturn(servletPath).anyTimes();
        expect(request.getPathInfo()).andReturn(pathInfo).anyTimes();
        replay(request);

        return request;
    }

    @BeforeEach
    public void setUp() {
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

    @MethodSource("generateParameters")
    @ParameterizedTest
    void testBasicAssumptions(String pattern, HttpServletRequest request, boolean shouldMatch) {
        initPathMatchingFilterParameterizedTest(pattern, request, shouldMatch);
        LOG.debug("Input pattern: [{}], input path: [{}].", this.pattern, this.request.getPathInfo());
        boolean matchEnabled = filter.pathsMatch(this.pattern, this.request);
        assertThat(matchEnabled).as("PathMatch can match URL end with multi Separator, ["
                + this.pattern + "] - [" + this.request.getPathInfo() + "]").isEqualTo(this.shouldMatch);
        verify(request);
    }

    public void initPathMatchingFilterParameterizedTest(String pattern, HttpServletRequest request, boolean shouldMatch) {
        this.pattern = pattern;
        this.request = request;
        this.shouldMatch = shouldMatch;
    }
}
