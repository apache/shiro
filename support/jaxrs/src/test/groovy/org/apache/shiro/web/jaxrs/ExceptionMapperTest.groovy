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

import org.apache.shiro.authz.AuthorizationException
import org.apache.shiro.authz.UnauthorizedException
import org.junit.Test

import javax.ws.rs.core.Response
import javax.ws.rs.ext.RuntimeDelegate

import static org.junit.Assert.assertSame
import static org.mockito.Mockito.*

/**
 * Tests for {@link ExceptionMapper}.
 * @since 1.4
 */
class ExceptionMapperTest {

    @Test
    void testUnauthorizedException() {

        doTest(new UnauthorizedException("expected test exception."), Response.Status.FORBIDDEN)
        doTest(new AuthorizationException("expected test exception."), Response.Status.UNAUTHORIZED)
        doTest(null, Response.Status.UNAUTHORIZED)
    }

    private void doTest(AuthorizationException exception , Response.StatusType expectedStatus) {
        def runtimeDelegate = mock(RuntimeDelegate)

        RuntimeDelegate.setInstance(runtimeDelegate)

        def responseBuilder = mock(Response.ResponseBuilder)
        def response = mock(Response)

        when(runtimeDelegate.createResponseBuilder()).then(args -> responseBuilder)
        when(responseBuilder.status((Response.StatusType) expectedStatus)).then(args -> responseBuilder)
        when(responseBuilder.build()).then(args -> response)

        def responseResult = new ExceptionMapper().toResponse(exception)
        assertSame response, responseResult

        verify(runtimeDelegate).createResponseBuilder()
        verify(responseBuilder).status((Response.StatusType) expectedStatus)
        verify(responseBuilder).build()
    }
}
