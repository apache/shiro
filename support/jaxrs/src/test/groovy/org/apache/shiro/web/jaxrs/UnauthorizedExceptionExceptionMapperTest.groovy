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
import org.apache.shiro.authz.HostUnauthorizedException
import org.apache.shiro.authz.UnauthenticatedException
import org.apache.shiro.authz.UnauthorizedException
import org.junit.jupiter.api.Test

import javax.ws.rs.core.Response
import javax.ws.rs.ext.ExceptionMapper

import static org.junit.jupiter.api.Assertions.assertEquals

/**
 * Tests for {@link UnauthorizedExceptionExceptionMapper}.
 * @since 1.4
 */
class UnauthorizedExceptionExceptionMapperTest {

    @Test
    void testUnauthorizedException() {
        doTest(new UnauthorizedException("expected test exception."), Response.Status.FORBIDDEN, new UnauthorizedExceptionExceptionMapper())
        doTest(new HostUnauthorizedException("expected test exception."), Response.Status.FORBIDDEN, new UnauthorizedExceptionExceptionMapper())
        doTest(new UnauthenticatedException("expected test exception."), Response.Status.UNAUTHORIZED, new UnauthenticatedExceptionExceptionMapper())
    }

    private static void doTest(AuthorizationException exception, Response.StatusType expectedStatus, ExceptionMapper<? extends Throwable> exceptionMapper) {
        final var response = exceptionMapper.toResponse(exception);
        assertEquals(expectedStatus.statusCode, response.status);
    }
}
