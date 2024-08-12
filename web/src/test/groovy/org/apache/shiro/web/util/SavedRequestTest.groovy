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

import org.junit.jupiter.api.Test

import jakarta.servlet.http.HttpServletRequest
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.easymock.EasyMock.niceMock
import static org.easymock.EasyMock.expect
import static org.easymock.EasyMock.replay
import static org.easymock.EasyMock.verify

class SavedRequestTest {

    @Test
    void testGetRequestUrl() {
        doTestGetRequestUrl("/foo//bar", "one=two&three=four", "/foo//bar?one=two&three=four")
        doTestGetRequestUrl("///foo//bar", "one=two&three=four", "/foo//bar?one=two&three=four")
        doTestGetRequestUrl("///foo//bar", "/foo//bar")
        doTestGetRequestUrl("/foo", "/foo")
        doTestGetRequestUrl("/", "one=two&three=four", "/?one=two&three=four")
        doTestGetRequestUrl("/", "/")
        doTestGetRequestUrl("//////", "/")
        doTestGetRequestUrl("", "")
    }

    private static void doTestGetRequestUrl(String requestURI, String expected) {
        doTestGetRequestUrl(requestURI, null, expected)
    }

    private static void doTestGetRequestUrl(String requestURI, String query, String expected) {
        HttpServletRequest request = niceMock(HttpServletRequest)
        expect(request.getRequestURI()).andReturn(requestURI)
        expect(request.getQueryString()).andReturn(query)
        replay request
        assertThat new SavedRequest(request).getRequestUrl(), equalTo(expected)
        verify request
    }
}
