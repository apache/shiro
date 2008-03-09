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

package org.jsecurity.web.authz;

import org.jsecurity.authc.AuthenticationException;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.codec.Base64;
import org.jsecurity.subject.Subject;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>Supports Basic HTTP Authentication. Class is RFC 2617 compliant.</p>
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
 * <p><code>Authorization: Basic *Base 64 encoded username and password token*</code></p>
 *
 * <p>In the case of this interceptor, the onUnAuthenticatedRequest(ServletRequest request, ServletResponse response) method will only be called if the subject making
 * the request is not authenticated.</p>
 *
 * @see <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>
 * @author Allan Ditzel
 * @since 0.9
 */
public class BasicHttpAuthenticationWebInterceptor extends AuthenticationWebInterceptor {

    protected static final String AUTHORIZATION_HEADER = "Authorization";
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";
    protected static final String CONTENT_TYPE_HEADER = "text/html";

    protected static final String UNAUTHORIZED_PAGE_HTML_CHUNK_1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n" +
            "<html><head>\n" +
            "<title>401 Unauthorized</title>\n" +
            "</head><body>\n" +
            "<h1>Unauthorized</h1>\n" +
            "<p>You must log in to access ";
    protected static final String UNAUTHORIZED_PAGE_HTML_CHUNK_2 = ".\n<hr>\n<address>";
    protected static final String UNAUTHORIZED_PAGE_HTML_CHUNK_3 = "</address>\n </body></html>";

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
    protected boolean onUnAuthenticatedRequest(ServletRequest request, ServletResponse response) {
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

        HttpServletResponse httpResponse = toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String authenticateHeader = HttpServletRequest.BASIC_AUTH + " realm=\"" + applicationName + "\"";
        httpResponse.setHeader(AUTHENTICATE_HEADER, authenticateHeader);

        // Commented out so we can do testing on what happens if we don't send a body. Considering this due
        // to internationalization issues.
//        String contentBody = buildContentBody(toHttp(request));
//
//        httpResponse.setContentLength(contentBody.length());
//        httpResponse.setContentType(CONTENT_TYPE_HEADER);
//
//        try {
//            PrintWriter printWriter = httpResponse.getWriter();
//            printWriter.write(contentBody);
//            httpResponse.flushBuffer();
//
//        } catch (IOException ioe) {
//            if (log.isErrorEnabled()) {
//                log.error("Error sending response.", ioe);
//            }
//        }

        return false;
    }

    /**
     * Builds the body of the response that will be sent back to the client.
     *
     * @param request
     * @return the string representation of the message body
     */
    protected String buildContentBody(HttpServletRequest request) {
        StringBuilder contentBody = new StringBuilder();

        contentBody.append(UNAUTHORIZED_PAGE_HTML_CHUNK_1);
        contentBody.append(request.getRequestURI());
        contentBody.append(UNAUTHORIZED_PAGE_HTML_CHUNK_2);
        contentBody.append(request.getServerName());
        contentBody.append(" Port ");
        contentBody.append(request.getServerPort());
        contentBody.append(UNAUTHORIZED_PAGE_HTML_CHUNK_3);

        return contentBody.toString();
    }

    /**
     * Initiates a login attempt with the provided credentials in the http header.
     *
     * @param request
     * @param response
     * @return true if the subject was successfully logged in, false otherwise
     */
    protected boolean executeLogin(ServletRequest request, ServletResponse response) {
        boolean isLoggedIn = false;

        HttpServletRequest httpRequest = toHttp(request);
        String authorizationHeader = httpRequest.getHeader(AUTHORIZATION_HEADER);

        if (authorizationHeader != null && authorizationHeader.length() > 0) {
            String[] authTokens = authorizationHeader.split(" ");
            if (authTokens[0].equals(HttpServletRequest.BASIC_AUTH)) {
                String encodedCredentials = authTokens[1];

                byte[] decodedCredentialByteArray = Base64.decodeBase64(encodedCredentials);
                String decodedCredentials = new String(decodedCredentialByteArray);

                String[] credentials = decodedCredentials.split(":");

                if (credentials != null && credentials.length > 1) {
                    Subject subject = getSubject(request, response);
                    UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(credentials[0], credentials[1]);
                    try {
                        subject.login(usernamePasswordToken);
                        isLoggedIn = true;
                    } catch (AuthenticationException ae) {
                        if (log.isDebugEnabled()) {
                            log.debug("Unable to log in subject.", ae);
                        }
                    }
                }
            }
        }

        return isLoggedIn;
    }
}
