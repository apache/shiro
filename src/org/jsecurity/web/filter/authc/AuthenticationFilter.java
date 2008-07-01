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

import org.jsecurity.subject.Subject;
import org.jsecurity.web.SavedRequest;
import org.jsecurity.web.WebUtils;
import static org.jsecurity.web.WebUtils.*;
import org.jsecurity.web.filter.PathMatchingFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * <p>Base class for all Filters that require the current user to be authenticated. This class encapsulates the
 * logic of checking whether a user is already authenticated in the system. If the user is not authenticated, we use
 * the template method pattern to delegate the processing of an unauthenticated request to sub classes.</p>
 *
 * @author Allan Ditzel
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class AuthenticationFilter extends PathMatchingFilter {

    // Key used when storing a SavedRequest in the session
    public static final String DEFAULT_LOGIN_URL = "/login.jsp";
    public static final String DEFAULT_SUCCESS_URL = "/index.jsp";
    public static final String SAVED_REQUEST_KEY = "jsecuritySavedRequest";
    protected static final String GET_METHOD = "get";

    private String successUrl = DEFAULT_SUCCESS_URL;
    private String loginUrl = DEFAULT_LOGIN_URL;

    protected String getLoginUrl() {
        return loginUrl;
    }

    /**
     * Sets the login URL used when a user needs to be redirected for authentication.
     * @param loginUrl the login URL.
     */
    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }


    protected String getSuccessUrl() {
        return successUrl;
    }

    /**
     * Sets the success URL that is the default location a user is sent to after logging in when
     * {@link #issueSuccessRedirect(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     * is called by subclasses of this filter.
     * @param successUrl the success URL to redirect the user to after a successful login.
     */
    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }
    

    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        //mapped value is ignored - not needed for most (if not all) authc Filters.
        if (isAccessAllowed(request, response)) {
            return true;
        } else {
            return onUnauthenticatedRequest(request, response);
        }
    }

    /**
     * Determines whether the current subject is authenticated.
     *
     * @param request the servlet request.
     * @param response the servlet response.
     * @return true if the subject is authenticated; false if the subject is unauthenticated
     */
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response) {
        if( isLoginRequest(request, response ) ) {
            return true;
        } else {
            Subject subject = getSubject(request, response);
            return subject.isAuthenticated();
        }
    }

    protected boolean isLoginRequest(ServletRequest servletRequest, ServletResponse response) {
        HttpServletRequest request = toHttp(servletRequest);
        String requestURI = getPathWithinApplication(request);
        return pathMatcher.match(getLoginUrl(), requestURI);
    }
    
    protected void saveRequest(ServletRequest servletRequest, ServletResponse response) {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpSession session = request.getSession();

        SavedRequest savedRequest = new SavedRequest(request);
        session.setAttribute( SAVED_REQUEST_KEY, savedRequest );
    }

    protected void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        saveRequest(request, response);
        WebUtils.issueRedirect(request, response, getLoginUrl());
    }

    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {

        String successUrl = null;
        SavedRequest savedRequest = getAndClearSavedRequest(request);
        if( savedRequest != null && savedRequest.getMethod().equalsIgnoreCase( GET_METHOD ) ) {
            successUrl = savedRequest.getRequestUrl();
        }

        if( successUrl == null ) {
            successUrl = getSuccessUrl();
        }

        if( successUrl == null ) {
            throw new IllegalArgumentException( "Success URL not available via saved request or by calling getSuccessUrl().  " +
                    "One of these must be non-null for issueSuccessRedirect() to work." );
        }

        WebUtils.issueRedirect( request, response, getSuccessUrl() );
    }

    protected SavedRequest getAndClearSavedRequest(ServletRequest request) {
        SavedRequest savedRequest = null;

        HttpSession session = WebUtils.toHttp(request).getSession(false);
        if( session != null ) {
            savedRequest = (SavedRequest) session.getAttribute( SAVED_REQUEST_KEY );
            if( savedRequest != null ) {
                session.removeAttribute( SAVED_REQUEST_KEY );
            }
        }

        return savedRequest;
    }

    /**
     * Template method sub-classes must implement. This method processes requests where the subject is not
     * authenticated.
     *
     * @param request the servlet request.
     * @param response the servlet response.
     * @return true if the request should continue to be processed; false if the subclass will handle/render
     *         the response directly.
     * @throws Exception if there is an error processing the unauthenticated request.
     */
    protected abstract boolean onUnauthenticatedRequest(ServletRequest request, ServletResponse response) throws Exception;
}
