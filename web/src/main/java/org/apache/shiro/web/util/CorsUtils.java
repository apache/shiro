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
package org.apache.shiro.web.util;

import org.apache.shiro.lang.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Utility class for CORS request handling based on the W3.
 *
 * @see <a href="https://fetch.spec.whatwg.org/#http-cors-protocol">CORS W3C recommendation</a>
 * @since 2.0.7
 */
public interface CorsUtils {

    /**
     * The HTTP {@code Origin} header field name.
     * @see <a href="https://tools.ietf.org/html/rfc6454">RFC 6454</a>
     */
    String ORIGIN = "Origin";
    /**
     * The CORS {@code Access-Control-Request-Method} request header field name.
     * @see <a href="https://www.w3.org/TR/cors/">CORS W3C recommendation</a>
     */
    String ACCESS_CONTROL_REQUEST_METHOD = "Access-Control-Request-Method";

    String OPTIONS = "OPTIONS";

    /**
     * Determines whether the given {@link HttpServletRequest} represents a CORS preflight request.
     * <p>
     * A CORS preflight request is an {@code OPTIONS} request sent by browsers before the actual
     * cross-origin request, to verify that the target server allows the actual request's
     * method and headers.
     * </p>
     *
     * <p>This method returns {@code true} if and only if:</p>
     * <ul>
     *   <li>The HTTP method is {@code OPTIONS},</li>
     *   <li>The {@code Origin} header is present, and</li>
     *   <li>The {@code Access-Control-Request-Method} header is present.</li>
     * </ul>
     *
     * @param request the incoming HTTP request to inspect (must not be {@code null})
     * @return {@code true} if the request is a valid CORS preflight request; {@code false} otherwise
     */
    static boolean isPreFlightRequest(HttpServletRequest request) {
        return (request.getMethod().equals(OPTIONS)
                && StringUtils.hasText(request.getHeader(ORIGIN))
                && StringUtils.hasText(request.getHeader(ACCESS_CONTROL_REQUEST_METHOD)));
    }
}
