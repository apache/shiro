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
import org.jsecurity.web.AbstractWebInterceptor;

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
public abstract class AuthenticationWebInterceptor extends AbstractWebInterceptor {

    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        if (isSubjectAuthenticated(request, response)) {
            return true;
        } else {
            return onUnAuthenticatedRequest(request, response);
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
     * @return true if the request should continue to be processed; false if the request should not continue to be
     * processed.
     */
    protected abstract boolean onUnAuthenticatedRequest(ServletRequest request, ServletResponse response);
}
