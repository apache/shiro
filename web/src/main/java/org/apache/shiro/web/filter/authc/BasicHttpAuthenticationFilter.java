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

import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.lang.codec.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;


/**
 * Requires the requesting user to be {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated} for the
 * request to continue, and if they're not, requires the user to login via the HTTP Basic protocol-specific challenge.
 * Upon successful login, they're allowed to continue on to the requested resource/url.
 * <p/>
 * This implementation is a 'clean room' Java implementation of Basic HTTP Authentication specification per
 * <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>.
 * <p/>
 * Basic authentication functions as follows:
 * <ol>
 * <li>A request comes in for a resource that requires authentication.</li>
 * <li>The server replies with a 401 response status, sets the <code>WWW-Authenticate</code> header, and the contents of a
 * page informing the user that the incoming resource requires authentication.</li>
 * <li>Upon receiving this <code>WWW-Authenticate</code> challenge from the server, the client then takes a
 * username and a password and puts them in the following format:
 * <p><code>username:password</code></p></li>
 * <li>This token is then base 64 encoded.</li>
 * <li>The client then sends another request for the same resource with the following header:<br/>
 * <p><code>Authorization: Basic <em>Base64_encoded_username_and_password</em></code></p></li>
 * </ol>
 * The {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method will
 * only be called if the subject making the request is not
 * {@link org.apache.shiro.subject.Subject#isAuthenticated() authenticated}
 *
 * @see <a href="https://tools.ietf.org/html/rfc2617">RFC 2617</a>
 * @see <a href="http://en.wikipedia.org/wiki/Basic_access_authentication">Basic Access Authentication</a>
 * @since 0.9
 */
public class BasicHttpAuthenticationFilter extends HttpAuthenticationFilter {

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(BasicHttpAuthenticationFilter.class);


    public BasicHttpAuthenticationFilter() {
        setAuthcScheme(HttpServletRequest.BASIC_AUTH);
        setAuthzScheme(HttpServletRequest.BASIC_AUTH);
    }

    /**
     * Creates an AuthenticationToken for use during login attempt with the provided credentials in the http header.
     * <p/>
     * This implementation:
     * <ol><li>acquires the username and password based on the request's
     * {@link #getAuthzHeader(javax.servlet.ServletRequest) authorization header} via the
     * {@link #getPrincipalsAndCredentials(String, javax.servlet.ServletRequest) getPrincipalsAndCredentials} method</li>
     * <li>The return value of that method is converted to an <code>AuthenticationToken</code> via the
     * {@link #createToken(String, String, javax.servlet.ServletRequest, javax.servlet.ServletResponse) createToken} method</li>
     * <li>The created <code>AuthenticationToken</code> is returned.</li>
     * </ol>
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse (never used)
     * @return the AuthenticationToken used to execute the login attempt
     */
    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            // Create an empty authentication token since there is no
            // Authorization header.
            return createToken("", "", request, response);
        }

        log.debug("Attempting to execute login with auth header");

        String[] prinCred = getPrincipalsAndCredentials(authorizationHeader, request);
        if (prinCred == null || prinCred.length < 2) {
            // Create an authentication token with an empty password,
            // since one hasn't been provided in the request.
            String username = prinCred == null || prinCred.length == 0 ? "" : prinCred[0];
            return createToken(username, "", request, response);
        }

        String username = prinCred[0];
        String password = prinCred[1];

        return createToken(username, password, request, response);
    }

    /**
     * Returns the username and password pair based on the specified <code>encoded</code> String obtained from
     * the request's authorization header.
     * <p/>
     * Per RFC 2617, the default implementation first Base64 decodes the string and then splits the resulting decoded
     * string into two based on the ":" character.  That is:
     * <p/>
     * <code>String decoded = Base64.decodeToString(encoded);<br/>
     * return decoded.split(":");</code>
     *
     * @param scheme  the {@link #getAuthcScheme() authcScheme} found in the request
     *                {@link #getAuthzHeader(javax.servlet.ServletRequest) authzHeader}.  It is ignored by this implementation,
     *                but available to overriding implementations should they find it useful.
     * @param encoded the Base64-encoded username:password value found after the scheme in the header
     * @return the username (index 0)/password (index 1) pair obtained from the encoded header data.
     */
    @Override
    protected String[] getPrincipalsAndCredentials(String scheme, String encoded) {
        String decoded = Base64.decodeToString(encoded);
        return decoded.split(":", 2);
    }
}
