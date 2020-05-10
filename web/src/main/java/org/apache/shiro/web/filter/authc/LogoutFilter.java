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

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.session.SessionException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.servlet.AdviceFilter;
import org.apache.shiro.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import java.util.Locale;

/**
 * Simple Filter that, upon receiving a request, will immediately log-out the currently executing
 * {@link #getSubject(javax.servlet.ServletRequest, javax.servlet.ServletResponse) subject}
 * and then redirect them to a configured {@link #getRedirectUrl() redirectUrl}.
 *
 * @since 1.2
 */
public class LogoutFilter extends AdviceFilter {
    
    private static final Logger log = LoggerFactory.getLogger(LogoutFilter.class);

    /**
     * The default redirect URL to where the user will be redirected after logout.  The value is {@code "/"}, Shiro's
     * representation of the web application's context root.
     */
    public static final String DEFAULT_REDIRECT_URL = "/";

    /**
     * The URL to where the user will be redirected after logout.
     */
    private String redirectUrl = DEFAULT_REDIRECT_URL;

    /**
     * Due to browser pre-fetching, using a GET requests for logout my cause a user to be logged accidentally, for example:
     * out while typing in an address bar.  If <code>postOnlyLogout</code> is <code>true</code>. Only POST requests will cause
     * a logout to occur.
     */
    private boolean postOnlyLogout = false;

    /**
     * Acquires the currently executing {@link #getSubject(javax.servlet.ServletRequest, javax.servlet.ServletResponse) subject},
     * a potentially Subject or request-specific
     * {@link #getRedirectUrl(javax.servlet.ServletRequest, javax.servlet.ServletResponse, org.apache.shiro.subject.Subject) redirectUrl},
     * and redirects the end-user to that redirect url.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code false} always as typically no further interaction should be done after user logout.
     * @throws Exception if there is any error.
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

        Subject subject = getSubject(request, response);

        // Check if POST only logout is enabled
        if (isPostOnlyLogout()) {

            // check if the current request's method is a POST, if not redirect
            if (!WebUtils.toHttp(request).getMethod().toUpperCase(Locale.ENGLISH).equals("POST")) {
               return onLogoutRequestNotAPost(request, response);
            }
        }

        String redirectUrl = getRedirectUrl(request, response, subject);
        //try/catch added for SHIRO-298:
        try {
            subject.logout();
        } catch (SessionException ise) {
            log.debug("Encountered session exception during logout.  This can generally safely be ignored.", ise);
        }
        issueRedirect(request, response, redirectUrl);
        return false;
    }

    /**
     * Returns the currently executing {@link Subject}.  This implementation merely defaults to calling
     * {@code SecurityUtils.}{@link org.apache.shiro.SecurityUtils#getSubject() getSubject()}, but can be overridden
     * by subclasses for different retrieval strategies.
     *
     * @param request  the incoming Servlet request
     * @param response the outgoing Servlet response
     * @return the currently executing {@link Subject}.
     */
    protected Subject getSubject(ServletRequest request, ServletResponse response) {
        return SecurityUtils.getSubject();
    }

    /**
     * Issues an HTTP redirect to the specified URL after subject logout.  This implementation simply calls
     * {@code WebUtils.}{@link WebUtils#issueRedirect(javax.servlet.ServletRequest, javax.servlet.ServletResponse, String) issueRedirect(request,response,redirectUrl)}.
     *
     * @param request  the incoming Servlet request
     * @param response the outgoing Servlet response
     * @param redirectUrl the URL to where the browser will be redirected immediately after Subject logout.
     * @throws Exception if there is any error.
     */
    protected void issueRedirect(ServletRequest request, ServletResponse response, String redirectUrl) throws Exception {
        WebUtils.issueRedirect(request, response, redirectUrl);
    }

    /**
     * Returns the redirect URL to send the user after logout.  This default implementation ignores the arguments and
     * returns the static configured {@link #getRedirectUrl() redirectUrl} property, but this method may be overridden
     * by subclasses to dynamically construct the URL based on the request or subject if necessary.
     * <p/>
     * Note: the Subject is <em>not</em> yet logged out at the time this method is invoked.  You may access the Subject's
     * session if one is available and if necessary.
     * <p/>
     * Tip: if you need to access the Subject's session, consider using the
     * {@code Subject.}{@link Subject#getSession(boolean) getSession(false)} method to ensure a new session isn't created unnecessarily.
     * If a session would be created, it will be immediately stopped after logout, not providing any value and
     * unnecessarily taxing session infrastructure/resources.
     *
     * @param request the incoming Servlet request
     * @param response the outgoing ServletResponse
     * @param subject the not-yet-logged-out currently executing Subject
     * @return the redirect URL to send the user after logout.
     */
    protected String getRedirectUrl(ServletRequest request, ServletResponse response, Subject subject) {
        return getRedirectUrl();
    }

    /**
     * Returns the URL to where the user will be redirected after logout.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @return the URL to where the user will be redirected after logout.
     */
    public String getRedirectUrl() {
        return redirectUrl;
    }

    /**
     * Sets the URL to where the user will be redirected after logout.  Default is the web application's context
     * root, i.e. {@code "/"}
     *
     * @param redirectUrl the url to where the user will be redirected after logout
     */
    @SuppressWarnings("unused")
    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }


    /**
     * This method is called when <code>postOnlyLogout</code> is <code>true</code>, and the request was NOT a <code>POST</code>.
     * For example if this filter is bound to '/logout' and the caller makes a GET request, this method would be invoked.
     * <p>
     *     The default implementation sets the response code to a 405, and sets the 'Allow' header to 'POST', and
     *     always returns false.
     * </p>
     *
     * @return The return value indicates if the processing should continue in this filter chain.
     */
    protected boolean onLogoutRequestNotAPost(ServletRequest request, ServletResponse response) {

        HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
        httpServletResponse.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpServletResponse.setHeader("Allow", "POST");
        return false;
    }

    /**
     * Due to browser pre-fetching, using a GET requests for logout my cause a user to be logged accidentally, for example:
     * out while typing in an address bar.  If <code>postOnlyLogout</code> is <code>true</code>. Only POST requests will cause
     * a logout to occur.
     *
     * @return Returns true if POST only logout is enabled
     */
    public boolean isPostOnlyLogout() {
        return postOnlyLogout;
    }

    /**
     * Due to browser pre-fetching, using a GET requests for logout my cause a user to be logged accidentally, for example:
     * out while typing in an address bar.  If <code>postOnlyLogout</code> is <code>true</code>. Only POST requests will cause
     * a logout to occur.
     * @param postOnlyLogout enable or disable POST only logout.
     */
    public void setPostOnlyLogout(boolean postOnlyLogout) {
        this.postOnlyLogout = postOnlyLogout;
    }
}
