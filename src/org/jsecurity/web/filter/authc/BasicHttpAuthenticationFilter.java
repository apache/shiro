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
package org.jsecurity.web.filter.authc;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.codec.Base64;
import org.jsecurity.subject.Subject;
import static org.jsecurity.web.WebUtils.toHttp;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Requires the requesting user to be {@link org.jsecurity.subject.Subject#isAuthenticated() authenticated} for the
 * request to continue, and if they're not, forces the user to login via the HTTP Basic protocol-specific challenge.
 * Upon successful login, they're allowed to continue on to the requested resource/url.
 *
 * <p>This implementation supports Basic HTTP Authentication as specified in
 * <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>.</p>
 *
 * <p>Basic authentication works as follows:</p>
 *
 * <ol>
 * <li>A request comes in for a resource that requires authentication.</li>
 * <li>The server replies with a 401 response code, a <code>WWW-Authenticate</code> header, and the contents of a
 * page informing the user that the incoming resource requires authentication.</li>
 * <li>Upon receiving this <code>WWW-Authenticate</code> challenge from the server, the client then takes a
 * username and a password and puts them in the following format:
 * <p><code>username:password</code></p></li>
 * <li>This token is then base 64 encoded.</li>
 * <li>The client then sends another request for the same resource with the following header:<p/>
 * <p><code>Authorization: Basic <em>Base64_encoded_username_and_password</em></code></p></li>
 * </ol>
 *
 * <p>The {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method will
 * only be called if the subject making the request is not
 * {@link org.jsecurity.subject.Subject#isAuthenticated() authenticated} </p>
 *
 * @author Allan Ditzel
 * @author Les Hazlewood
 * @see <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>
 * @since 0.9
 */
public class BasicHttpAuthenticationFilter extends AuthenticationFilter {

    protected static final String AUTHORIZATION_HEADER = "Authorization";
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    /**
     * The name that is displayed during the challenge process of authentication.
     */
    private String applicationName = "application";

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * Method processes unauthenticated requests. It handles the two-stage request/challenge authentication request.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return true if the request should be processed; false if the request should not continue to be processed
     */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) {
        boolean allowed = false; //denied by default
        if (isLoginAttempt(request, response)) {
            allowed = executeLogin(request, response);
        }
        if (!allowed) {
            sendChallenge(request, response);
        }
        return allowed;
    }

    /**
     * Determines whether the incoming request is an attempt to log in.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return true if the incoming request is an attempt to log in, false otherwise
     */
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        HttpServletRequest httpRequest = toHttp(request);
        String authorizationHeader = httpRequest.getHeader(AUTHORIZATION_HEADER);
        return authorizationHeader != null;
    }

    /**
     * Builds the challenge for authorization.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return false - this sends the challenge to be sent back
     */
    protected boolean sendChallenge(ServletRequest request, ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication required: sending 401 Authentication challenge response.");
        }
        HttpServletResponse httpResponse = toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String authenticateHeader = HttpServletRequest.BASIC_AUTH + " realm=\"" + getApplicationName() + "\"";
        httpResponse.setHeader(AUTHENTICATE_HEADER, authenticateHeader);
        return false;
    }

    /**
     * Initiates a login attempt with the provided credentials in the http header.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return true if the subject was successfully logged in, false otherwise
     */
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Attempting to authenticate Subject based on Http BASIC Authentication request...");
        }

        HttpServletRequest httpRequest = toHttp(request);
        String authorizationHeader = httpRequest.getHeader(AUTHORIZATION_HEADER);

        if (authorizationHeader != null && authorizationHeader.length() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Executing login with headers [" + authorizationHeader + "]");
            }

            String[] authTokens = authorizationHeader.split(" ");

            if (authTokens[0].trim().equalsIgnoreCase(HttpServletRequest.BASIC_AUTH)) {
                String encodedCredentials = authTokens[1];

                String decodedCredentials = Base64.decodeToString(encodedCredentials);

                String[] credentials = decodedCredentials.split(":");

                if (credentials != null && credentials.length > 1) {
                    if (log.isDebugEnabled()) {
                        log.debug("Processing login request [" + credentials[0] + "]");
                    }
                    Subject subject = getSubject(request, response);
                    UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(credentials[0], credentials[1]);
                    try {
                        subject.login(usernamePasswordToken);
                        if (log.isDebugEnabled()) {
                            log.debug("Successfully logged in user [" + credentials[0] + "]");
                        }
                        return true;
                    } catch (AuthenticationException ae) {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to log in subject [" + credentials[0] + "]", ae);
                        }
                    }
                }
            }
        }

        //always default to false.  If we've made it to this point in the code, that
        //means the authentication attempt either never occured, or wasn't successful:
        return false;
    }
}
