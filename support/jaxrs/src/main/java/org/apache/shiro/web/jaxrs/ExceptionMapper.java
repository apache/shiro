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
package org.apache.shiro.web.jaxrs;


import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.UnauthorizedException;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

/**
 * JAX-RS exception mapper used to map Shiro {@link AuthorizationExceptions} to HTTP status codes.
 * {@link UnauthorizedException} will be mapped to 403, all others 401.
 * @since 1.4
 */
public class ExceptionMapper implements javax.ws.rs.ext.ExceptionMapper<AuthorizationException> {

    @Override
    public Response toResponse(AuthorizationException exception) {

        Status status;

        if (exception instanceof UnauthorizedException) {
            status = Status.FORBIDDEN;
        } else {
            status = Status.UNAUTHORIZED;
        }

        return Response.status(status).build();
    }
}
