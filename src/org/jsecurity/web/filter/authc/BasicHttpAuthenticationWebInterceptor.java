/*
 * Copyright (C) 2005-2008 Allan Ditzel
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
 * Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the
 *
 * Free Software Foundation, Inc.
 * 59 Temple Place, Suite 330
 * Boston, MA 02111-1307
 * USA
 *
 * Or, you may view it online at
 * http://www.opensource.org/licenses/lgpl-license.php
 */

package org.jsecurity.web.filter.authc;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.codec.Base64;
import org.jsecurity.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Supports Basic HTTP Authentication as specified in
 * <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>.</p>
 *
 * <p>Basic authentication works as follows:</p>
 *
 * <p>A request comes in for a resource that requires authentication. The server replies with a 401 response
 * code, a <code>WWW-Authenticate</code> header, and the contents of a page informing the user that the incoming resource
 * requires authentication.</p>
 *
 * <p>Upon receiving the <code>WWW-Authenticate</code> challenge from the server, the client then takes a username and a password
 * and puts them in the following format:</p>
 *
 * <p><code>username:password</code></p>
 *
 * <p>This token is then base 64 encoded.</p>
 *
 * <p>The client then sends another request for the same resource with the following header:</p>
 *
 * <p><code>Authorization: Basic <em>Base64_encoded_username_and_password</em></code></p>
 *
 * <p>In the case of this interceptor, the onUnauthenticatedRequest(ServletRequest request, ServletResponse response) method will only be called if the subject making
 * the request is not authenticated.</p>
 *
 * @see <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>
 * @author Allan Ditzel
 * @since 0.9
 */
public class BasicHttpAuthenticationWebInterceptor extends AuthenticationWebInterceptor {

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
     * @param request
     * @param response
     * @return true if the request should be processed; false if the request should not continue to be processed
     */
    protected boolean onUnauthenticatedRequest(ServletRequest request, ServletResponse response) {
        if (isLoginAttempt(request, response)) {
            return executeLogin(request, response);
        } else {
            return sendChallenge(request, response);
        }
    }

    /**
     * Determines whether the incoming request is an attempt to log in.
     *
     * @param request
     * @param response
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
     * @param request
     * @param response
     * @return false - this sends the challenge to be sent back 
     */
    protected boolean sendChallenge(ServletRequest request, ServletResponse response) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Authentication required: sending 401 Authentication challenge response." );
        }
        HttpServletResponse httpResponse = toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String authenticateHeader = HttpServletRequest.BASIC_AUTH + " realm=\"" + applicationName + "\"";
        httpResponse.setHeader(AUTHENTICATE_HEADER, authenticateHeader);
        return false;
    }

    /**
     * Initiates a login attempt with the provided credentials in the http header.
     *
     * @param request
     * @param response
     * @return true if the subject was successfully logged in, false otherwise
     */
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        if ( log.isDebugEnabled() ) {
            log.debug( "Attempting to authenticate Subject based on Http BASIC Authentication request..." );
        }
        boolean isLoggedIn = false;

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
                        isLoggedIn = true;
                    } catch (AuthenticationException ae) {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to log in subject [" + credentials[0] + "]", ae);
                        }

                        return sendChallenge(request, response);
                    }
                }
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Returning [" + isLoggedIn + "] from executeLogin()");
        }

        return isLoggedIn;
    }
}
