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
package org.apache.shiro.web.filter.authz;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.lang.util.StringUtils;
import org.apache.shiro.web.filter.AccessControlFilter;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Superclass for authorization-related filters.  If an request is unauthorized, response handling is delegated to the
 * {@link #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse) onAccessDenied} method, which
 * provides reasonable handling for most applications.
 *
 * @see #onAccessDenied(javax.servlet.ServletRequest, javax.servlet.ServletResponse)
 * @since 0.9
 */
public abstract class AuthorizationFilter extends AccessControlFilter {

    /**
     * The URL to which users should be redirected if they are denied access to an underlying path or resource,
     * {@code null} by default which will issue a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response
     * (401 Unauthorized).
     */
    private String unauthorizedUrl;

    /**
     * Returns the URL to which users should be redirected if they are denied access to an underlying path or resource,
     * or {@code null} if a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response should be issued (401 Unauthorized).
     * <p/>
     * The default is {@code null}, ensuring default web server behavior.  Override this default by calling the
     * {@link #setUnauthorizedUrl(String) setUnauthorizedUrl} method with a meaningful path within your application
     * if you would like to show the user a 'nice' page in the event of unauthorized access.
     *
     * @return the URL to which users should be redirected if they are denied access to an underlying path or resource,
     *         or {@code null} if a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response should be issued (401 Unauthorized).
     */
    public String getUnauthorizedUrl() {
        return unauthorizedUrl;
    }

    /**
     * Sets the URL to which users should be redirected if they are denied access to an underlying path or resource.
     * <p/>
     * If the value is {@code null} a raw {@link HttpServletResponse#SC_UNAUTHORIZED} response will
     * be issued (401 Unauthorized), retaining default web server behavior.
     * <p/>
     * Unless overridden by calling this method, the default value is {@code null}.  If desired, you can specify a
     * meaningful path within your application if you would like to show the user a 'nice' page in the event of
     * unauthorized access.
     *
     * @param unauthorizedUrl the URL to which users should be redirected if they are denied access to an underlying
     *                        path or resource, or {@code null} to a ensure raw {@link HttpServletResponse#SC_UNAUTHORIZED} response is
     *                        issued (401 Unauthorized).
     */
    public void setUnauthorizedUrl(String unauthorizedUrl) {
        this.unauthorizedUrl = unauthorizedUrl;
    }

    /**
     * Handles the response when access has been denied.  It behaves as follows:
     * <ul>
     * <li>If the {@code Subject} is unknown<sup><a href="#known">[1]</a></sup>:
     * <ol><li>The incoming request will be saved and they will be redirected to the login page for authentication
     * (via the {@link #saveRequestAndRedirectToLogin(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     * method).</li>
     * <li>Once successfully authenticated, they will be redirected back to the originally attempted page.</li></ol>
     * </li>
     * <li>If the Subject is known:</li>
     * <ol>
     * <li>The HTTP {@link HttpServletResponse#SC_UNAUTHORIZED} header will be set (401 Unauthorized)</li>
     * <li>If the {@link #getUnauthorizedUrl() unauthorizedUrl} has been configured, a redirect will be issued to that
     * URL.  Otherwise the 401 response is rendered normally</li>
     * </ul>
     * <code><a name="known">[1]</a></code>: A {@code Subject} is 'known' when
     * <code>subject.{@link org.apache.shiro.subject.Subject#getPrincipal() getPrincipal()}</code> is not {@code null},
     * which implicitly means that the subject is either currently authenticated or they have been remembered via
     * 'remember me' services.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return {@code false} always for this implementation.
     * @throws IOException if there is any servlet error.
     */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {

        Subject subject = getSubject(request, response);
        // If the subject isn't identified, redirect to login URL
        if (subject.getPrincipal() == null) {
            saveRequestAndRedirectToLogin(request, response);
        } else {
            // If subject is known but not authorized, redirect to the unauthorized URL if there is one
            // If no unauthorized URL is specified, just return an unauthorized HTTP status code
            String unauthorizedUrl = getUnauthorizedUrl();
            //SHIRO-142 - ensure that redirect _or_ error code occurs - both cannot happen due to response commit:
            if (StringUtils.hasText(unauthorizedUrl)) {
                WebUtils.issueRedirect(request, response, unauthorizedUrl);
            } else {
                WebUtils.toHttp(response).sendError(HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
        return false;
    }

}
