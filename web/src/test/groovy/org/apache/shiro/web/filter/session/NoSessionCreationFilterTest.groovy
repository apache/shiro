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
package org.apache.shiro.web.filter.session

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.apache.shiro.subject.support.DefaultSubjectContext
import org.junit.Test

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Unit tests for the {@link NoSessionCreationFilter} implementation.
 *
 * @since 1.2
 */
class NoSessionCreationFilterTest {

    @Test
    void testDefault() {
        NoSessionCreationFilter filter = new NoSessionCreationFilter();

        def request = createStrictMock(ServletRequest)
        def response = createStrictMock(ServletResponse)

        request.setAttribute(eq(DefaultSubjectContext.SESSION_CREATION_ENABLED), eq(Boolean.FALSE))

        replay request, response

        assertTrue filter.onPreHandle(request, response, null)

        verify request, response
    }
}
