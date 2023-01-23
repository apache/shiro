/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.shiro.ee.filters;

import org.apache.shiro.ee.filters.AuthenticationFilterDelegate.MethodsFromFilter;
import static org.apache.shiro.ee.filters.FormResubmitSupport.getReferer;
import org.apache.shiro.ee.filters.Forms.FallbackPredicate;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import lombok.experimental.Delegate;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;

/**
 * JSF Ajax support for logout
 */
public class LogoutFilter extends org.apache.shiro.web.filter.authc.LogoutFilter {
    static final FallbackPredicate YES_PREDICATE = createPredicate();
    static final String LOGOUT_PREDICATE_ATTR_NAME = "org.apache.shiro.ee.logout-predicate";
    private final @Delegate AuthenticationFilterDelegate delegate;

    private class Methods implements MethodsFromFilter {
        @Override
        public Subject getSubject(ServletRequest request, ServletResponse response) {
            return LogoutFilter.super.getSubject(request, response);
        }

        @Override
        public boolean isLoginRequest(ServletRequest request, ServletResponse response) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getLoginUrl() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
            return LogoutFilter.super.preHandle(request, response);
        }

        @Override
        public boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                ServletRequest request, ServletResponse response) {
            throw new UnsupportedOperationException();
        }
    }

    public LogoutFilter() {
        delegate = new AuthenticationFilterDelegate(new Methods());
    }

    @Override
    protected void issueRedirect(ServletRequest request, ServletResponse response, String redirectUrl) throws Exception {
        if (request instanceof HttpServletRequest) {
            FallbackPredicate logoutFallbackType = (FallbackPredicate) request.getAttribute(LOGOUT_PREDICATE_ATTR_NAME);
            Forms.logout(WebUtils.toHttp(request), WebUtils.toHttp(response), logoutFallbackType, redirectUrl);
        } else {
            super.issueRedirect(request, response, redirectUrl);
        }
    }

    static FallbackPredicate createPredicate() {
        return (String path, HttpServletRequest request) -> {
            String referer = getReferer(request);
            return !path.equals(referer);
        };
    }
}
