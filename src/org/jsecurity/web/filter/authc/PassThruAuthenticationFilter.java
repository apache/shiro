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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * An authentication filter that redirects the user to the login page when they are trying to access
 * a protected resource.  However, if the user is trying to access the login page, the filter lets
 * the request pass through to the application code.
 * <p/>
 * The difference between this controller and the {@link FormAuthenticationFilter} is that on a login submission
 * (by default an HTTP POST to the login URL), the form controller attempts to automatically authenticate the
 * user by passing the "username" and "password" request parameter values to
 * {@link org.jsecurity.subject.Subject#login(org.jsecurity.authc.AuthenticationToken)}.
 * <p/>
 * This controller always passes all requests to the login URL through, both GETs and POSTs.
 * This is useful in cases where the developer
 * wants to write their own login behavior, which should include a call to
 * {@link org.jsecurity.subject.Subject#login(org.jsecurity.authc.AuthenticationToken)} at some point.  For example,
 * if the developer has a login controller or validator with custom login behavior, this controller may be
 * appropriate.
 *
 * @author Jeremy Haile
 * @since 0.9
 * @see FormAuthenticationFilter
 */
public class PassThruAuthenticationFilter extends AuthenticationFilter {

    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            saveRequestAndRedirectToLogin(request, response);
            return false;
        }
    }

}
