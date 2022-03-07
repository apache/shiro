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
package org.apache.shiro.spring.web

import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.web.util.UrlPathHelper

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo

/**
 * Tests a couple known differences between the stock and the ShiroUrlPathHelper
 */
class ShiroUrlPathHelperTest {

    @Test
    void testGetPathWithinApplication() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/foo/%2e%2e")
        assertThat new UrlPathHelper().getPathWithinApplication(request), equalTo("/foo/..")
        assertThat new ShiroUrlPathHelper().getPathWithinApplication(request), equalTo("/")
    }

    @Test
    void testGetPathWithinServletMapping() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/foo/%2e%2e")
        assertThat new UrlPathHelper().getPathWithinServletMapping(request), equalTo("/foo/..")
        assertThat new ShiroUrlPathHelper().getPathWithinServletMapping(request), equalTo("/")
    }
}