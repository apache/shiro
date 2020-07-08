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

import org.junit.Test

import javax.servlet.http.HttpServletRequest

import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.mock
import static org.easymock.EasyMock.replay
import static org.hamcrest.MatcherAssert.assertThat

class InvalidRequestFilterTest {

    @Test
    void defaultConfig() {
        InvalidRequestFilter filter = new InvalidRequestFilter()
        assertThat "filter.blockBackslash expected to be true", filter.isBlockBackslash()
        assertThat "filter.blockNonAscii expected to be true", filter.isBlockNonAscii()
        assertThat "filter.blockSemicolon expected to be true", filter.isBlockSemicolon()
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
    }


    static void assertPathBlocked(InvalidRequestFilter filter, String path) {
        assertThat "Expected path '${path}', to be blocked", !filter.isAccessAllowed(mockRequest(path), null, null)
    }

    static void assertPathAllowed(InvalidRequestFilter filter, String path) {
        assertThat "Expected path '${path}', to be allowed", filter.isAccessAllowed(mockRequest(path), null, null)
    }

    static HttpServletRequest mockRequest(String path) {
        HttpServletRequest request = mock(HttpServletRequest)
        expect(request.getRequestURI()).andReturn(path)
        replay(request)
        return request
    }
}
