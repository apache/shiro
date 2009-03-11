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
package org.apache.ki.web.filter.authz;

import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.ki.subject.Subject;
import org.apache.ki.util.StringUtils;
import org.apache.ki.web.WebUtils;
import org.apache.ki.web.filter.AccessControlFilter;

/**
 * Superclass for authorization-related filters.  For unauthorized requests, this filter redirects to the
 * login page if the current user is unknown (i.e. not authenticated or remembered).  If the user is known,
 * the filter redirects to an unauthorized URL or returns an unauthorized HTTP status code if no unauthorized
 * URL is specified.
 *
 * @author Les Hazlewood
 * @author Jeremy Haile
 * @since 0.9
 */
public abstract class AuthorizationFilter extends AccessControlFilter {

    //TODO - complete JavaDoc

    private String unauthorizedUrl;

    protected String getUnauthorizedUrl() {
        return unauthorizedUrl;
    }

    public void setUnauthorizedUrl(String unauthorizedUrl) {
        this.unauthorizedUrl = unauthorizedUrl;
    }

    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {

        Subject subject = getSubject(request, response);
        // If the subject isn't identified, redirect to login URL
        if (subject.getPrincipal() == null) {
            saveRequestAndRedirectToLogin(request, response);
            return false;
        } else {

            // If subject is known but not authorized, redirect to the unauthorized URL if there is one 
            // If no unauthorized URL is specified, just return an unauthorized HTTP status code
            WebUtils.toHttp(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            if (StringUtils.hasText(getUnauthorizedUrl())) {
                WebUtils.issueRedirect(request, response, getUnauthorizedUrl());
            }

        }
        return false;
    }

}
