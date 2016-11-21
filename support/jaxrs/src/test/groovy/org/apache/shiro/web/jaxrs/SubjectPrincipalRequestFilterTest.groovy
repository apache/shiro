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
package org.apache.shiro.web.jaxrs

import org.easymock.Capture
import org.junit.Test

import javax.ws.rs.container.ContainerRequestContext
import javax.ws.rs.core.SecurityContext

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

/**
 * Tests for {@link SubjectPrincipalRequestFilter}.
 * @since 1.4
 */
class SubjectPrincipalRequestFilterTest {

    @Test
    void testWrapContext() {
        def filter = new SubjectPrincipalRequestFilter()

        def contextCapture = new Capture<ShiroSecurityContext>()
        def requestContext = mock(ContainerRequestContext)
        def originalSecurityContext = mock(SecurityContext)
        expect(requestContext.getSecurityContext()).andReturn(originalSecurityContext)
        expect(requestContext.setSecurityContext(capture(contextCapture)))
        replay requestContext, originalSecurityContext

        filter.filter(requestContext)

        verify requestContext, originalSecurityContext
        assertSame requestContext, contextCapture.value.containerRequestContext
    }

}
