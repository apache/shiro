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
package org.jsecurity.web.filter;

import org.jsecurity.web.WebUtils;
import static org.jsecurity.web.WebUtils.getPathWithinApplication;
import static org.jsecurity.web.WebUtils.toHttp;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Superclass for any filter that controls access to a resource and may redirect the user to the login page
 * if they are not authenticated.  This superclass provides the method {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
 * which is used by many subclasses as the behavior when a user is unauthenticated.
 *
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class AccessControlFilter extends PathMatchingFilter{

    // Key used when storing a SavedRequest in the session
    public static final String DEFAULT_LOGIN_URL = "/login.jsp";
    protected static final String GET_METHOD = "get";

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

    /**
     * Template method subclasses must implement.  This method determines whether or not the request is allowed to
     * proceed normally, or whether the request should be handled by the logic in
     * {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}.
     *
     * @param request the request.
     * @param response the response.
     * @param mappedValue the value mapped to this filter in the URL rules.
     * @return true if the reques should proceed normally, false if the request should be proceessed by this filter's
     * {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse)} method.
     * @throws IOException if an error occurs during processing.
     */
    protected abstract boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception;

    /**
     * Template method sub-classes must implement. This method processes requests where the subject was denied access
     * by the {@link #isAccessAllowed(javax.servlet.ServletRequest, javax.servlet.ServletResponse, Object)} method.
     *
     * @param request the servlet request.
     * @param response the servlet response.
     * @return true if the request should continue to be processed; false if the subclass will handle/render
     *         the response directly.
     * @throws Exception if there is an error processing the request.
     */
    protected abstract boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception;


    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        //mapped value is ignored - not needed for most (if not all) authc Filters.
        if (isAccessAllowed(request, response, mappedValue)) {
            return true;
        } else {
            return onAccessDenied(request, response);
        }
    }

    protected boolean isLoginRequest(ServletRequest servletRequest, ServletResponse response) {
        HttpServletRequest request = toHttp(servletRequest);
        String requestURI = getPathWithinApplication(request);
        return pathMatcher.match(getLoginUrl(), requestURI);
    }

    protected void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        WebUtils.saveRequest(request);
        WebUtils.issueRedirect(request, response, getLoginUrl());
    }

}
