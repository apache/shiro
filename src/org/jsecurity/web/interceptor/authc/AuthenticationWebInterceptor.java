/*
 * Copyright 2005-2008 Allan Ditzel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jsecurity.web.interceptor.authc;

import org.jsecurity.subject.Subject;
import static org.jsecurity.web.WebUtils.getSubject;
import org.jsecurity.web.interceptor.PathMatchingWebInterceptor;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * <p>Base class for all web interceptors that require authentication. This class encapsulates the logic of checking
 * whether a user is already authenticated in the system. If the user is not authenticated, we use the template
 * method pattern to delegate the processing of an unauthenticated request to sub classes.</p>
 *
 * @author Allan Ditzel
 * @since 0.9
 */
public abstract class AuthenticationWebInterceptor extends PathMatchingWebInterceptor {

    public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
        //mapped value is ignored - not needed for most (if not all) authc interceptors.
        if (isSubjectAuthenticated(request, response)) {
            return true;
        } else {
            return onUnauthenticatedRequest(request, response);
        }
    }

    /**
     * Determines whether the current subject is authenticated.
     *
     * @param request
     * @param response
     * @return true if the subject is authenticated; false if the subject is unauthenticated
     */
    private boolean isSubjectAuthenticated(ServletRequest request, ServletResponse response) {
        Subject subject = getSubject(request, response);
        return subject.isAuthenticated();
    }

    /**
     * Template method sub-classes must implement. This method processes requests where the subject is not
     * authenticated.
     *
     * @param request
     * @param response
     * @return true if the request should continue to be processed; false if the subclass will handle/render
     *         the response directly.
     */
    protected abstract boolean onUnauthenticatedRequest(ServletRequest request, ServletResponse response) throws Exception;
}
