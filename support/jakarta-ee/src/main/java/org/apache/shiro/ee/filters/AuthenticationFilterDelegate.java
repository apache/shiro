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

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.SneakyThrows;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.ee.filters.Forms.FallbackPredicate;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_PREDICATE_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_URL_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_WAITTIME_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormAuthenticationFilter.NO_PREDICATE;
import static org.apache.shiro.ee.filters.FormResubmitSupport.savePostDataForResubmit;
import static org.apache.shiro.ee.filters.FormResubmitSupport.saveRequestReferer;
import static org.apache.shiro.ee.filters.LogoutFilter.LOGOUT_PREDICATE_ATTR_NAME;
import static org.apache.shiro.ee.filters.LogoutFilter.YES_PREDICATE;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitDisabled;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isServletNoPrincipal;
import static org.apache.shiro.web.jaxrs.SubjectPrincipalRequestFilter.SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM;

/**
 * common functionality for both Form and PassThru authentication filters
 */
@RequiredArgsConstructor
class AuthenticationFilterDelegate {
    interface MethodsFromFilter {
        Subject getSubject(ServletRequest request, ServletResponse response);

        boolean isLoginRequest(ServletRequest request, ServletResponse response);

        String getLoginUrl();

        boolean preHandle(ServletRequest request, ServletResponse response) throws Exception;

        boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                               ServletRequest request, ServletResponse response);
    }

    private final MethodsFromFilter methods;
    /**
     * true if rememberMe cookie is set and valid
     */
    private @Getter
    @Setter boolean useRemembered;
    /**
     * number of seconds to sleep if authentication fails
     */
    private @Getter
    @Setter int loginFailedWaitTime;
    private @Getter
    @Setter FallbackPredicate loginFallbackType = NO_PREDICATE;
    private @Getter
    @Setter FallbackPredicate logoutFallbackType = YES_PREDICATE;

    public boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        request.setAttribute(LOGIN_PREDICATE_ATTR_NAME, loginFallbackType);
        request.setAttribute(LOGIN_WAITTIME_ATTR_NAME, loginFailedWaitTime);
        request.setAttribute(LOGOUT_PREDICATE_ATTR_NAME, logoutFallbackType);
        if (isServletNoPrincipal(request.getServletContext())) {
            request.setAttribute(SHIRO_WEB_JAXRS_DISABLE_PRINCIPAL_PARAM, Boolean.TRUE);
        }
        try {
            request.setAttribute(LOGIN_URL_ATTR_NAME, methods.getLoginUrl());
        } catch (UnsupportedOperationException e) {
            // LogoutFilter does not support this, safely ignore
        }
        return methods.preHandle(request, response);
    }

    /**
     * added remembered functionality
     *
     * @param request
     * @param response
     * @param mappedValue
     * @return access allowed
     */
    public boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        Subject subject = methods.getSubject(request, response);
        boolean isAuthenticated = subject.isAuthenticated() && subject.getPrincipal() != null;
        return isAuthenticated || (useRemembered && subject.isRemembered());
    }

    /**
     * added form save for resubmit functionality
     *
     * @param request
     * @param response
     * @throws IOException
     */
    public void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        if (request instanceof HttpServletRequest && !isFormResubmitDisabled(request.getServletContext())) {
            savePostDataForResubmit(WebUtils.toHttp(request), WebUtils.toHttp(response),
                    methods.getLoginUrl());
        }
    }

    /**
     * in case the login link is clicked directly,
     * redirect to referer
     *
     * @param request
     * @param response
     * @return
     */
    public boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        boolean rv = methods.isLoginRequest(request, response);
        if (request instanceof HttpServletRequest) {
            saveRequestReferer(rv, WebUtils.toHttp(request), WebUtils.toHttp(response));
        }
        return rv;
    }

    @SneakyThrows(InterruptedException.class)
    public boolean onLoginFailure(AuthenticationToken token, AuthenticationException e,
                                  ServletRequest request, ServletResponse response) {
        if (loginFailedWaitTime != 0) {
            TimeUnit.SECONDS.sleep(loginFailedWaitTime);
        }
        return methods.onLoginFailure(token, e, request, response);
    }

    /**
     * combine the two because response is unavailable in saveRequest()
     *
     * @param request
     * @param response
     * @throws IOException
     */
    public void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        if (request instanceof HttpServletRequest) {
            FormResubmitSupport.saveRequest(WebUtils.toHttp(request), WebUtils.toHttp(response), false);
        }
        redirectToLogin(request, response);
    }

    public void saveRequest(ServletRequest request) {
        throw new UnsupportedOperationException("bad op");
    }
}
