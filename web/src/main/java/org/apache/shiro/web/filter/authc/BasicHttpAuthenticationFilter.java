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
import org.apache.shiro.codec.Base64;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


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
 * @see <a href="ftp://ftp.isi.edu/in-notes/rfc2617.txt">RFC 2617</a>
 * @see <a href="http://en.wikipedia.org/wiki/Basic_access_authentication">Basic Access Authentication</a>
 * @since 0.9
 */
public class BasicHttpAuthenticationFilter extends AuthenticatingFilter {

    /**
     * This class's private logger.
     */
    private static final Logger log = LoggerFactory.getLogger(BasicHttpAuthenticationFilter.class);

    /**
     * HTTP Authorization header, equal to <code>Authorization</code>
     */
    protected static final String AUTHORIZATION_HEADER = "Authorization";

    /**
     * HTTP Authentication header, equal to <code>WWW-Authenticate</code>
     */
    protected static final String AUTHENTICATE_HEADER = "WWW-Authenticate";

    /**
     * The name that is displayed during the challenge process of authentication, defauls to <code>application</code>
     * and can be overridden by the {@link #setApplicationName(String) setApplicationName} method.
     */
    private String applicationName = "application";

    /**
     * The authcScheme to look for in the <code>Authorization</code> header, defaults to <code>BASIC</code>
     */
    private String authcScheme = HttpServletRequest.BASIC_AUTH;

    /**
     * The authzScheme value to look for in the <code>Authorization</code> header, defaults to <code>BASIC</code>
     */
    private String authzScheme = HttpServletRequest.BASIC_AUTH;

    /**
     * Returns the name to use in the ServletResponse's <b><code>WWW-Authenticate</code></b> header.
     * <p/>
     * Per RFC 2617, this name name is displayed to the end user when they are asked to authenticate.  Unless overridden
     * by the {@link #setApplicationName(String) setApplicationName(String)} method, the default value is 'application'.
     * <p/>
     * Please see {@link #setApplicationName(String) setApplicationName(String)} for an example of how this functions.
     *
     * @return the name to use in the ServletResponse's 'WWW-Authenticate' header.
     */
    public String getApplicationName() {
        return applicationName;
    }

    /**
     * Sets the name to use in the ServletResponse's <b><code>WWW-Authenticate</code></b> header.
     * <p/>
     * Per RFC 2617, this name name is displayed to the end user when they are asked to authenticate.  Unless overridden
     * by this method, the default value is &quot;application&quot;
     * <p/>
     * For example, setting this property to the value <b><code>Awesome Webapp</code></b> will result in the
     * following header:
     * <p/>
     * <code>WWW-Authenticate: Basic realm=&quot;<b>Awesome Webapp</b>&quot;</code>
     * <p/>
     * Side note: As you can see from the header text, the HTTP Basic specification calls
     * this the authentication 'realm', but we call this the 'applicationName' instead to avoid confusion with
     * Shiro's Realm constructs.
     *
     * @param applicationName the name to use in the ServletResponse's 'WWW-Authenticate' header.
     */
    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }

    /**
     * Returns the HTTP <b><code>Authorization</code></b> header value that this filter will respond to as indicating
     * a login request.
     * <p/>
     * Unless overridden by the {@link #setAuthzScheme(String) setAuthzScheme(String)} method, the
     * default value is <code>BASIC</code>.
     *
     * @return the Http 'Authorization' header value that this filter will respond to as indicating a login request
     */
    public String getAuthzScheme() {
        return authzScheme;
    }

    /**
     * Sets the HTTP <b><code>Authorization</code></b> header value that this filter will respond to as indicating a
     * login request.
     * <p/>
     * Unless overridden by this method, the default value is <code>BASIC</code>
     *
     * @param authzScheme the HTTP <code>Authorization</code> header value that this filter will respond to as
     *                    indicating a login request.
     */
    public void setAuthzScheme(String authzScheme) {
        this.authzScheme = authzScheme;
    }

    /**
     * Returns the HTTP <b><code>WWW-Authenticate</code></b> header scheme that this filter will use when sending
     * the HTTP Basic challenge response.  The default value is <code>BASIC</code>.
     *
     * @return the HTTP <code>WWW-Authenticate</code> header scheme that this filter will use when sending the HTTP
     *         Basic challenge response.
     * @see #sendChallenge
     */
    public String getAuthcScheme() {
        return authcScheme;
    }

    /**
     * Sets the HTTP <b><code>WWW-Authenticate</code></b> header scheme that this filter will use when sending the
     * HTTP Basic challenge response.  The default value is <code>BASIC</code>.
     *
     * @param authcScheme the HTTP <code>WWW-Authenticate</code> header scheme that this filter will use when
     *                    sending the Http Basic challenge response.
     * @see #sendChallenge
     */
    public void setAuthcScheme(String authcScheme) {
        this.authcScheme = authcScheme;
    }

    /**
     * Processes unauthenticated requests. It handles the two-stage request/challenge authentication protocol.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return true if the request should be processed; false if the request should not continue to be processed
     */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean loggedIn = false; //false by default or we wouldn't be in this method
        if (isLoginAttempt(request, response)) {
            loggedIn = executeLogin(request, response);
        }
        if (!loggedIn) {
            sendChallenge(request, response);
        }
        return loggedIn;
    }

    /**
     * Determines whether the incoming request is an attempt to log in.
     * <p/>
     * The default implementation obtains the value of the request's
     * {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER}, and if it is not <code>null</code>, delegates
     * to {@link #isLoginAttempt(String) isLoginAttempt(authzHeaderValue)}. If the header is <code>null</code>,
     * <code>false</code> is returned.
     *
     * @param request  incoming ServletRequest
     * @param response outgoing ServletResponse
     * @return true if the incoming request is an attempt to log in based, false otherwise
     */
    protected boolean isLoginAttempt(ServletRequest request, ServletResponse response) {
        String authzHeader = getAuthzHeader(request);
        return authzHeader != null && isLoginAttempt(authzHeader);
    }

    /**
     * Returns the {@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER} from the specified ServletRequest.
     * <p/>
     * This implementation merely casts the request to an <code>HttpServletRequest</code> and returns the header:
     * <p/>
     * <code>HttpServletRequest httpRequest = {@link WebUtils#toHttp(javax.servlet.ServletRequest) toHttp(reaquest)};<br/>
     * return httpRequest.getHeader({@link #AUTHORIZATION_HEADER AUTHORIZATION_HEADER});</code>
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return the <code>Authorization</code> header's value.
     */
    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpRequest = WebUtils.toHttp(request);
        return httpRequest.getHeader(AUTHORIZATION_HEADER);
    }

    /**
     * Default implementation that returns <code>true</code> if the specified <code>authzHeader</code>
     * starts with the same (case-insensitive) characters specified by the
     * {@link #getAuthzScheme() authzScheme}, <code>false</code> otherwise.
     * <p/>
     * That is:
     * <p/>
     * <code>String authzScheme = getAuthzScheme().toLowerCase();<br/>
     * return authzHeader.toLowerCase().startsWith(authzScheme);</code>
     *
     * @param authzHeader the 'Authorization' header value (guaranteed to be non-null if the
     *                    {@link #isLoginAttempt(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method is not overriden).
     * @return <code>true</code> if the authzHeader value matches that configured as defined by
     *         the {@link #getAuthzScheme() authzScheme}.
     */
    protected boolean isLoginAttempt(String authzHeader) {
        String authzScheme = getAuthzScheme().toLowerCase();
        return authzHeader.toLowerCase().startsWith(authzScheme);
    }

    /**
     * Builds the challenge for authorization by setting a HTTP <code>401</code> (Unauthorized) status as well as the
     * response's {@link #AUTHENTICATE_HEADER AUTHENTICATE_HEADER}.
     * <p/>
     * The header value constructed is equal to:
     * <p/>
     * <code>{@link #getAuthcScheme() getAuthcScheme()} + " realm=\"" + {@link #getApplicationName() getApplicationName()} + "\"";</code>
     *
     * @param request  incoming ServletRequest, ignored by this implementation
     * @param response outgoing ServletResponse
     * @return false - this sends the challenge to be sent back
     */
    protected boolean sendChallenge(ServletRequest request, ServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Authentication required: sending 401 Authentication challenge response.");
        }
        HttpServletResponse httpResponse = WebUtils.toHttp(response);
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String authcHeader = getAuthcScheme() + " realm=\"" + getApplicationName() + "\"";
        httpResponse.setHeader(AUTHENTICATE_HEADER, authcHeader);
        return false;
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
     * @param response outgoing ServletResponse
     * @return the AuthenticationToken used to execute the login attempt
     */
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String authorizationHeader = getAuthzHeader(request);
        if (authorizationHeader == null || authorizationHeader.length() == 0) {
            // Create an empty authentication token since there is no
            // Authorization header.
            return createToken("", "", request, response);
        }

        if (log.isDebugEnabled()) {
            log.debug("Attempting to execute login with headers [" + authorizationHeader + "]");
        }

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
     * Returns the username obtained from the
     * {@link #getAuthzHeader(javax.servlet.ServletRequest) authorizationHeader}.
     * <p/>
     * Once the {@code authzHeader} is split per the RFC (based on the space character ' '), the resulting split tokens
     * are translated into the username/password pair by the
     * {@link #getPrincipalsAndCredentials(String, String) getPrincipalsAndCredentials(scheme,encoded)} method.
     *
     * @param authorizationHeader the authorization header obtained from the request.
     * @param request             the incoming ServletRequest
     * @return the username (index 0)/password pair (index 1) submitted by the user for the given header value and request.
     * @see #getAuthzHeader(javax.servlet.ServletRequest)
     */
    protected String[] getPrincipalsAndCredentials(String authorizationHeader, ServletRequest request) {
        if (authorizationHeader == null) {
            return null;
        }
        String[] authTokens = authorizationHeader.split(" ");
        if (authTokens == null || authTokens.length < 2) {
            return null;
        }
        return getPrincipalsAndCredentials(authTokens[0], authTokens[1]);
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
    protected String[] getPrincipalsAndCredentials(String scheme, String encoded) {
        String decoded = Base64.decodeToString(encoded);
        return decoded.split(":");
    }
}
