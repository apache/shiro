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
package org.apache.shiro.web.filter.authc;

import org.apache.shiro.authc.BearerToken;
import org.apache.shiro.authc.AuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;


/**
 * Requires the requesting user to be {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated} for the
 * request to continue, and if they're not, requires the user to login via the HTTP Bearer protocol-specific challenge.
 * Upon successful login, they're allowed to continue on to the requested resource/url.
 * <p/>
 * The {@link #onAccessDenied(ServletRequest, ServletResponse)} method will
 * only be called if the subject making the request is not
 * {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated}
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2.1">OAuth2 Authorization Request Header Field</a>
 * @since 1.5
 */
public class BearerHttpAuthenticationFilter extends HttpAuthenticationFilter {

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(BearerHttpAuthenticationFilter.class);

    private static final String BEARER = "Bearer";

    public BearerHttpAuthenticationFilter() {
        setAuthcScheme(BEARER);
        setAuthzScheme(BEARER);
    }

    /**
     * Creates an AuthenticationToken for use during login attempt with the provided credentials in the http header.
     * <p/>
     * This implementation:
     * <ol><li>acquires the username and password based on the request's
     * {@link #getAuthzHeader(ServletRequest) authorization header} via the
     * {@link #getPrincipalsAndCredentials(String, ServletRequest) getPrincipalsAndCredentials} method</li>
     * <li>The return value of that method is converted to an <code>AuthenticationToken</code> via the
     * {@link #createToken(String, String, ServletRequest, ServletResponse) createToken} method</li>
     * <li>The created <code>AuthenticationToken</code> is returned.</li>
     * </ol>
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return the AuthenticationToken used to execute the login attempt
     */
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            // Create an empty authentication token since there is no
            // Authorization header.
            return createBearerToken("", request);
        }

        log.debug("Attempting to execute login with auth header");

        String[] prinCred = getPrincipalsAndCredentials(authorizationHeader, request);
        if (prinCred == null || prinCred.length < 1) {
            // Create an authentication token with an empty password,
            // since one hasn't been provided in the request.
            return createBearerToken("", request);
        }

        String token = prinCred[0] != null ? prinCred[0] : "";
        return createBearerToken(token, request);
    }
    @Override
    protected String[] getPrincipalsAndCredentials(String scheme, String token) {
        return new String[] {token};
    }

    protected AuthenticationToken createBearerToken(String token, ServletRequest request) {
        return new BearerToken(token, request.getRemoteHost());
    }
}
