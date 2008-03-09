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

import org.jsecurity.subject.Subject;
import org.jsecurity.codec.Base64;
import org.jsecurity.authc.AuthenticationToken;
import org.jsecurity.authc.UsernamePasswordToken;
import org.jsecurity.authc.AuthenticationException;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Supports Basic HTTP Authentication. Class is RFC 2616 compliant (http://www.w3.org/Protocols/rfc2616/rfc2616.html).
 *
 * Basic authentication works as follows:
 *
 * A request comes in for a resource that requires authorization. The server replies with a 401 response
 * code, a WWW-Authenticate header, and the contents of a page informing the user that the incoming resource
 * requires authorization.
 *
 * Upon receiving the WWW-Authenticate challenge from the server, the client then takes a username and a password
 * and puts them in the following format:
 *
 * username:password
 *
 * This token is then base 64 encoded.
 *
 * The client then sends another request for the same resource with the following header:
 *
 * Authorization: Basic *Base 64 encoded username and password token*
 *
 * In the case of this interceptor, the onAunAuthenticatedRequest() method will only be called if the subject making
 * the request is not authenticated.
 *
 * @since: 0.9
 *
 * @author: Allan Ditzel
 */
public class BasicHttpAuthenticationWebInterceptor extends AuthenticatorWebInterceptor {

    protected static final String AUTHORIZATION_HEADER = "Authorization";
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";
    protected static final String CONTENT_TYPE_HEADER = "text/html";

    protected static final String UNAUTHORIZED_PAGE_HTML = "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n" +
            " \"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\n" +
            "<HTML>\n" +
            "  <HEAD>\n" +
            "    <TITLE>Error</TITLE>\n" +
            "    <META HTTP-EQUIV=\"Content-Type\" CONTENT=\"text/html; charset=ISO-8859-1\">\n" +
            "  </HEAD>\n" +
            "  <BODY><H1>401 Unauthorised.</H1></BODY>\n" +
            "</HTML>";

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

        return authorizationHeader == null ? false : true;
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
        httpResponse.setContentLength(UNAUTHORIZED_PAGE_HTML.length());
        httpResponse.setContentType(CONTENT_TYPE_HEADER);

        try {
            PrintWriter printWriter = httpResponse.getWriter();
            printWriter.write(UNAUTHORIZED_PAGE_HTML);
            httpResponse.flushBuffer();

        } catch (IOException ioe) {
            if (log.isErrorEnabled()) {
                log.error("Error sending response.", ioe);
            }
        }

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
                    UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken();
                    usernamePasswordToken.setUsername(credentials[0]);
                    usernamePasswordToken.setPassword(credentials[1].toCharArray());
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
