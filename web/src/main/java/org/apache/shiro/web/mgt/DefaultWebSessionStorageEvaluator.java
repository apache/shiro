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
package org.apache.shiro.web.mgt;

import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;

/**
 * A web-specific {@code SessionStorageEvaluator} that performs the same logic as the parent class
 * {@link DefaultSessionStorageEvaluator} but additionally checks for a request-specific flag that may enable or
 * disable session access.
 * <p/>
 * This implementation usually works in conjunction with the
 * {@link org.apache.shiro.web.filter.session.NoSessionCreationFilter NoSessionFilter}:  If the {@code NoSessionFilter}
 * is configured in a filter chain, that filter will set a specific
 * {@code ServletRequest} {@link javax.servlet.ServletRequest#setAttribute attribute} indicating that session creation
 * should be disabled.
 * <p/>
 * This {@code DefaultWebSessionStorageEvaluator} will then inspect this attribute, and if it has been set, will return
 * {@code false} from {@link #isSessionStorageEnabled(org.apache.shiro.subject.Subject)} method, thereby preventing
 * Shiro from creating a session for the purpose of storing subject state.
 * <p/>
 * If the request attribute has
 * not been set (i.e. the {@code NoSessionFilter} is not configured or has been disabled), this class does nothing
 * and delegates to the parent class for existing behavior.
 *
 * @since 1.2
 */
public class DefaultWebSessionStorageEvaluator extends DefaultSessionStorageEvaluator {

    /**
     * Returns {@code true} if session storage is generally available (as determined by the super class's global
     * configuration property {@link #isSessionStorageEnabled()} and no request-specific override has turned off
     * session storage, {@code false} otherwise.
     * <p/>
     * This means session storage is disabled if the {@link #isSessionStorageEnabled()} property is {@code false} or if
     * a request attribute is discovered that turns off session storage for the current request.
     *
     * @param subject the {@code Subject} for which session state persistence may be enabled
     * @return {@code true} if session storage is generally available (as determined by the super class's global
     *         configuration property {@link #isSessionStorageEnabled()} and no request-specific override has turned off
     *         session storage, {@code false} otherwise.
     */
    @Override
    public boolean isSessionStorageEnabled(Subject subject) {
        if (subject.getSession(false) != null) {
            //use what already exists
            return true;
        }

        if (!isSessionStorageEnabled()) {
            //honor global setting:
            return false;
        }

        //at this point there is no session yet, but general session storage is allowed.  Let's check to see if there
        //is a request-specific override just in case:
        if (WebUtils.isWeb(subject)) {
            ServletRequest request = WebUtils.getRequest(subject);
            Object val = request.getAttribute(DefaultSubjectContext.SESSION_CREATION_ENABLED);
            if (val != null && val instanceof Boolean) {
                return (Boolean)val;
            }
        }

        //generally available and no request-specific override:
        return true;
    }


}