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

import java.util.function.Supplier;
import org.apache.shiro.ee.filters.AuthenticationFilterDelegate.MethodsFromFilter;
import static org.apache.shiro.ee.filters.FormResubmitSupport.redirectToSaved;
import org.apache.shiro.ee.filters.Forms.FallbackPredicate;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import lombok.experimental.Delegate;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;
import static org.omnifaces.facesviews.FacesViews.FACES_VIEWS_ORIGINAL_SERVLET_PATH;

/**
 * Implements JSF Ajax redirection via OmniFaces
 * Implements form resubmit and auto remember-me functionality
 */
public class FormAuthenticationFilter extends org.apache.shiro.web.filter.authc.FormAuthenticationFilter {
    static final String LOGIN_PREDICATE_ATTR_NAME = "org.apache.shiro.ee.login-predicate";
    static final String LOGIN_WAITTIME_ATTR_NAME = "org.apache.shiro.ee.login-wait-time";
    static final String LOGIN_URL_ATTR_NAME = "org.apache.shiro.ee.login-url";
    static final FallbackPredicate NO_PREDICATE = (path, request) -> false;
    private final @Delegate AuthenticationFilterDelegate delegate;

    private class Methods implements MethodsFromFilter {
        @Override
        public Subject getSubject(ServletRequest request, ServletResponse response) {
            return FormAuthenticationFilter.super.getSubject(request, response);
        }

        @Override
        public boolean isLoginRequest(ServletRequest request, ServletResponse response) {
            return FormAuthenticationFilter.super.isLoginRequest(request, response);
        }

        @Override
        public boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                ServletRequest request, ServletResponse response) {
            return FormAuthenticationFilter.super.onLoginFailure(token, e, request, response);
        }

        @Override
        public String getLoginUrl() {
            return FormAuthenticationFilter.super.getLoginUrl();
        }

        @Override
        public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
            return FormAuthenticationFilter.super.preHandle(request, response);
        }
    };

    public FormAuthenticationFilter() {
        delegate = new AuthenticationFilterDelegate(new Methods());
    }

    @Override
    protected boolean onLoginSuccess(AuthenticationToken token, Subject subject, ServletRequest request,
            ServletResponse response) throws Exception {
        if (request instanceof HttpServletRequest) {
            FallbackPredicate loginFallbackType = (FallbackPredicate) request.getAttribute(LOGIN_PREDICATE_ATTR_NAME);
            redirectToSaved(WebUtils.toHttp(request), WebUtils.toHttp(response), loginFallbackType, "");
        }
        return false;
    }

    @Override
    protected String getPathWithinApplication(ServletRequest request) {
        return getPathWithinApplication(request, () -> super.getPathWithinApplication(request));
    }

    static String getPathWithinApplication(ServletRequest request, Supplier<String> superMethod) {
        String origPath = (String) request.getAttribute(FACES_VIEWS_ORIGINAL_SERVLET_PATH);
        if (origPath != null) {
            return origPath;
        } else {
            return superMethod.get();
        }
    }
}
