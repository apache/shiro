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

package org.apache.shiro.web.filter

import org.apache.shiro.web.RestoreSystemProperties
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.parallel.Isolated

import jakarta.servlet.http.HttpServletRequest

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.mock
import static org.easymock.EasyMock.replay
import static org.hamcrest.MatcherAssert.assertThat

@Isolated("Uses System Properties")
class InvalidRequestFilterTest {

    @Test
    void defaultConfig() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        assertThat "filter.blockBackslash expected to be true", filter.isBlockBackslash()
        assertThat "filter.blockNonAscii expected to be true", filter.isBlockNonAscii()
        assertThat "filter.blockSemicolon expected to be true", filter.isBlockSemicolon()
        assertThat "filter.blockTraversal expected to be true", filter.isBlockTraversal()
        assertThat "filter.blockRewriteTraversal expected to be true", filter.isBlockRewriteTraversal()
        assertThat "filter.blockEncodedPeriod expected to be true", filter.isBlockEncodedPeriod()
        assertThat "filter.blockEncodedForwardSlash expected to be true", filter.isBlockEncodedForwardSlash()
    }

    @Test
    void systemPropertyAllowBackslash() {
        RestoreSystemProperties.withProperties(["org.apache.shiro.web.ALLOW_BACKSLASH": "true"]) {
            InvalidRequestFilter filter = new InvalidRequestFilter()
            assertThat "filter.blockBackslash expected to be false", !filter.isBlockBackslash()
        }

        RestoreSystemProperties.withProperties(["org.apache.shiro.web.ALLOW_BACKSLASH": ""]) {
            InvalidRequestFilter filter = new InvalidRequestFilter()
            assertThat "filter.blockBackslash expected to be false", filter.isBlockBackslash()
        }

        RestoreSystemProperties.withProperties(["org.apache.shiro.web.ALLOW_BACKSLASH": "false"]) {
            InvalidRequestFilter filter = new InvalidRequestFilter()
            assertThat "filter.blockBackslash expected to be false", filter.isBlockBackslash()
        }
    }

    @Test
    void testFilterBlocks() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        assertPathBlocked(filter, "/\\something")
        assertPathBlocked(filter, "/%5csomething")
        assertPathBlocked(filter, "/%5Csomething")
        assertPathBlocked(filter, "/;something")
        assertPathBlocked(filter, "/%3bsomething")
        assertPathBlocked(filter, "/%3Bsomething")
        assertPathBlocked(filter, "/\u0019something")

        assertPathBlocked(filter, "/something", "/;something")
        assertPathBlocked(filter, "/something", "/something", "/;")
        assertPathBlocked(filter, "/something", "/something", "/.;")
    }

    @Test
    void testBlocksTraversal() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        assertPathBlocked(filter, "/something/../")
        assertPathBlocked(filter, "/something/../bar")
        assertPathBlocked(filter, "/something/../bar/")
        assertPathBlocked(filter, "/something/..")
        assertPathBlocked(filter, "/..")
        assertPathBlocked(filter, "..")
        assertPathBlocked(filter, "../")
        assertPathBlocked(filter, "%2F./")
        assertPathBlocked(filter, "/something/./")
        assertPathBlocked(filter, "/something/./bar")
        assertPathBlocked(filter, "/something/\u002e/bar")
        assertPathBlocked(filter, "/something/./bar/")
        assertPathBlocked(filter, "/something/.")
        assertPathBlocked(filter, "/.")
        assertPathBlocked(filter, "/something/../something/.")
        assertPathBlocked(filter, "/something/../something/.")
        assertPathBlocked(filter, "/something/.;")
        assertPathBlocked(filter, "/something/%2e%3b")

        assertPathAllowed(filter, "/something/.bar")
        assertPathAllowed(filter, "/.something")
        assertPathAllowed(filter, ".something")
    }

    @Test
    void testBlocksEncodedPeriod() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        assertPathBlocked(filter, "/%2esomething")
        assertPathBlocked(filter, "%2esomething")
        assertPathBlocked(filter, "%2E./")
        assertPathBlocked(filter, "%2F./")
        assertPathBlocked(filter, "/something/%2e;")
        assertPathBlocked(filter, "/something/%2e%3b")
        assertPathBlocked(filter, "/something/%2e%2E/bar/")
        assertPathBlocked(filter, "/something/%2e/bar/")
    }

    @Test
    void testAllowsEncodedPeriod() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockEncodedPeriod(false)
        assertPathAllowed(filter, "/%2esomething")
        assertPathAllowed(filter, "%2esomething")
        assertPathAllowed(filter, "%2E./")
        assertPathAllowed(filter, "/something/%2e%2E/bar/")
        assertPathAllowed(filter, "/something/%2e/bar/")
    }

    @Test
    void testBlocksEncodedForwardSlash() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        assertPathBlocked(filter, "%2F./")
        assertPathBlocked(filter, "/something/%2f/bar/")
    }

    @Test
    void testAllowsEncodedForwardSlash() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockEncodedForwardSlash(false)
        assertPathAllowed(filter, "%2F./")
        assertPathAllowed(filter, "/something/%2f/bar/")
    }

    @Test
    void testBlocksRewriteTraversal() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockSemicolon(false)
        assertPathBlocked(filter, "/something/..;jsessionid=foobar")
        assertPathBlocked(filter, "/something/.;jsessionid=foobar")
    }

    @Test
    void testAllowRewriteTraversal() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockSemicolon(false)
        filter.setBlockRewriteTraversal(false)
        assertPathAllowed(filter, "/something/..;jsessionid=foobar")
        assertPathAllowed(filter, "/something/.;jsessionid=foobar")
    }

    @Test
    void testFilterAllowsBackslash() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockBackslash(false)
        assertPathAllowed(filter, "/\\something")
        assertPathAllowed(filter, "/%5csomething")
        assertPathAllowed(filter, "/%5Csomething")
        assertPathBlocked(filter, "/;something")
        assertPathBlocked(filter, "/%3bsomething")
        assertPathBlocked(filter, "/%3Bsomething")
        assertPathBlocked(filter, "/\u0019something")

        assertPathAllowed(filter, "/something", "/\\something")
        assertPathAllowed(filter, "/something", "/something", "/\\")
    }

    @Test
    void testFilterAllowsNonAscii() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockNonAscii(false)
        assertPathBlocked(filter, "/\\something")
        assertPathBlocked(filter, "/%5csomething")
        assertPathBlocked(filter, "/%5Csomething")
        assertPathBlocked(filter, "/;something")
        assertPathBlocked(filter, "/%3bsomething")
        assertPathBlocked(filter, "/%3Bsomething")
        assertPathAllowed(filter, "/\u0019something")

        assertPathAllowed(filter, "/something", "/\u0019something")
        assertPathAllowed(filter, "/something", "/something", "/\u0019")
    }

    @Test
    void testFilterAllowsSemicolon() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockSemicolon(false)
        assertPathBlocked(filter, "/\\something")
        assertPathBlocked(filter, "/%5csomething")
        assertPathBlocked(filter, "/%5Csomething")
        assertPathAllowed(filter, "/;something")
        assertPathAllowed(filter, "/%3bsomething")
        assertPathAllowed(filter, "/%3Bsomething")
        assertPathBlocked(filter, "/\u0019something")

        assertPathAllowed(filter, "/something", "/;something")
        assertPathAllowed(filter, "/something", "/something", "/;")
    }

    @Test
    void testAllowTraversal() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        filter.setBlockTraversal(false)

        assertPathAllowed(filter, "/something/../")
        assertPathAllowed(filter, "/something/../bar")
        assertPathAllowed(filter, "/something/../bar/")
        assertPathAllowed(filter, "/something/..")
        assertPathAllowed(filter, "/..")
        assertPathAllowed(filter, "..")
        assertPathAllowed(filter, "../")
        assertPathAllowed(filter, "/something/./")
        assertPathAllowed(filter, "/something/./bar")
        assertPathAllowed(filter, "/something/\u002e/bar")
        assertPathAllowed(filter, "/something\u002fbar")
        assertPathAllowed(filter, "/something/./bar/")
        assertPathAllowed(filter, "/something/.")
        assertPathAllowed(filter, "/.")
        assertPathAllowed(filter, "/something/../something/.")
    }

    static void assertPathBlocked(InvalidRequestFilter filter, String requestUri, String servletPath = requestUri, String pathInfo = null) {
        assertThat "Expected path '${requestUri}', to be blocked", !filter.isAccessAllowed(mockRequest(requestUri, servletPath, pathInfo), null, null)
    }

    static void assertPathAllowed(InvalidRequestFilter filter, String requestUri, String servletPath = requestUri, String pathInfo = null) {
        assertThat "Expected requestUri '${requestUri}', to be allowed", filter.isAccessAllowed(mockRequest(requestUri, servletPath, pathInfo), null, null)
    }

    static HttpServletRequest mockRequest(String requestUri, String servletPath, String pathInfo) {
        HttpServletRequest request = mock(HttpServletRequest)
        expect(request.getRequestURI()).andReturn(requestUri)
        expect(request.getServletPath()).andReturn(servletPath).anyTimes()
        expect(request.getPathInfo()).andReturn(pathInfo).anyTimes()
        expect(request.getAttribute("jakarta.servlet.include.servlet_path")).andReturn(servletPath)
        expect(request.getAttribute("jakarta.servlet.include.path_info")).andReturn(pathInfo)
        replay(request)
        return request
    }
}
