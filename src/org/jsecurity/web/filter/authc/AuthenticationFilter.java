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
import org.jsecurity.web.filter.AccessControlFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * <p>Base class for all Filters that require the current user to be authenticated. This class encapsulates the
 * logic of checking whether a user is already authenticated in the system. If the user is not authenticated, we use
 * the template method pattern to delegate the processing of an unauthenticated request to sub classes.</p>
 *
 * @author Allan Ditzel
 * @author Jeremy Haile
 * @author Les Hazlewood
 * @since 0.9
 */
public abstract class AuthenticationFilter extends AccessControlFilter {

    public static final String DEFAULT_SUCCESS_URL = "/index.jsp";

    private String successUrl = DEFAULT_SUCCESS_URL;

    protected String getSuccessUrl() {
        return successUrl;
    }

    /**
     * Sets the success URL that is the default location a user is sent to after logging in when
     * {@link #issueSuccessRedirect(javax.servlet.ServletRequest, javax.servlet.ServletResponse)}
     * is called by subclasses of this filter.
     *
     * @param successUrl the success URL to redirect the user to after a successful login.
     */
    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }


    /**
     * Determines whether the current subject is authenticated.
     * <p/>
     * The default implementation {@link #getSubject(javax.servlet.ServletRequest, javax.servlet.ServletResponse) acquires}
     * the currently executing Subject and then returns
     * {@link org.jsecurity.subject.Subject#isAuthenticated() subject.isAuthenticated()};
     *
     * @return true if the subject is authenticated; false if the subject is unauthenticated
     */
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = getSubject(request, response);
        return subject.isAuthenticated();
    }

    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {

        String successUrl = null;
        SavedRequest savedRequest = WebUtils.getAndClearSavedRequest(request);
        if (savedRequest != null && savedRequest.getMethod().equalsIgnoreCase(GET_METHOD)) {
            successUrl = savedRequest.getRequestUrl();
        }

        if (successUrl == null) {
            successUrl = getSuccessUrl();
        }

        if (successUrl == null) {
            throw new IllegalStateException("Success URL not available via saved request or by calling " +
                    "getSuccessUrl().  One of these must be non-null for issueSuccessRedirect() to work.");
        }

        WebUtils.issueRedirect(request, response, successUrl);
    }

}
