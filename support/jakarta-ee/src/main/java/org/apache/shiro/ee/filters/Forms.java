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

import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_PREDICATE_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormAuthenticationFilter.LOGIN_WAITTIME_ATTR_NAME;
import static org.apache.shiro.ee.filters.FormResubmitSupport.FORM_IS_RESUBMITTED;
import static org.apache.shiro.ee.filters.FormResubmitSupport.SESSION_EXPIRED_PARAMETER;
import static org.apache.shiro.ee.filters.LogoutFilter.LOGOUT_PREDICATE_ATTR_NAME;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResumbitDisabled;

import java.util.concurrent.TimeUnit;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;

import static org.apache.shiro.web.filter.authc.FormAuthenticationFilter.DEFAULT_ERROR_KEY_ATTRIBUTE_NAME;
import static org.omnifaces.exceptionhandler.ViewExpiredExceptionHandler.wasViewExpired;

import org.omnifaces.util.Faces;

/**
 * Methods to redirect to saved requests upon logout
 * functionality includes saving a previous form state and resubmitting
 * if the form times out
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings("HideUtilityClassConstructor")
public class Forms {
    /**
     * JSF access points
     */
    @Named("authc")
    @ApplicationScoped
    public static class AuthenticationMethods {
        /**
         * let Shiro filter handle the login,
         * this method should only get called if login fails
         * login wait time is handled by Shiro configuration
         */
        public void login() {
            if (isLoginFailure()) {
                loginFailed();
            } else if (!redirectIfLoggedIn()) {
                throw new IllegalStateException("Not enough context to log in, need username / password");
            }
        }

        /**
         * manual login, zero wait time
         *
         * @param username
         * @param password
         */
        public void login(String username, String password) {
            login(username, password, false);
        }

        /**
         * manual login with timeout
         *
         * @param username
         * @param password
         * @param rememberMe
         */
        public void login(String username, String password, boolean rememberMe) {
            Forms.login(username, password, rememberMe);
        }

        public void logout() {
            Forms.logout();
        }

        public boolean isLoggedIn() {
            return Forms.isLoggedIn();
        }

        public boolean redirectIfLoggedIn() {
            return redirectIfLoggedIn("");
        }

        public boolean redirectIfLoggedIn(String view) {
            if (isLoggedIn()) {
                redirectToView(Faces.getRequestAttribute(LOGOUT_PREDICATE_ATTR_NAME), view);
                return true;
            } else {
                return false;
            }
        }

        public boolean isSessionExpired() {
            return Forms.isSessionExpired();
        }

        public boolean isLoginFailure() {
            return Faces.getRequestAttribute(DEFAULT_ERROR_KEY_ATTRIBUTE_NAME) != null
                    || Faces.getFlashAttribute(DEFAULT_ERROR_KEY_ATTRIBUTE_NAME) != null;
        }
    }

    @FunctionalInterface
    public interface FallbackPredicate {
        boolean useFallback(String path, HttpServletRequest request);
    }

    /**
     * Jakarta Faces variant
     * redirect to saved request, possibly resubmitting an existing form
     * the saved request is via a cookie
     *
     * @param useFallbackPath
     * @param fallbackPath
     */
    public static void redirectToSaved(FallbackPredicate useFallbackPath, String fallbackPath) {
        FormResubmitSupport.redirectToSaved(Faces.getRequest(), Faces.getResponse(), useFallbackPath, fallbackPath,
                !isFormResumbitDisabled(Faces.getRequest().getServletContext()));
    }

    /**
     * Jakarta Faces variant
     * redirects to current view after a form submit, or a logout, for example
     */
    public static void redirectToView() {
        FormResubmitSupport.redirectToView(Faces.getRequest(), Faces.getResponse());
    }

    public static void redirectToView(FallbackPredicate useFallbackPath, String fallbackPath) {
        FormResubmitSupport.redirectToView(Faces.getRequest(), Faces.getResponse(), useFallbackPath, fallbackPath);
    }

    /**
     * manually login, used via {@link PassThruAuthenticationFilter}
     *
     * @param username
     * @param password
     * @param rememberMe
     */
    @SneakyThrows(InterruptedException.class)
    public static void login(String username, String password, boolean rememberMe) {
        try {
            SecurityUtils.getSubject().login(new UsernamePasswordToken(username, password, rememberMe));
            redirectToSaved(Faces.getRequestAttribute(LOGIN_PREDICATE_ATTR_NAME), "");
        } catch (AuthenticationException e) {
            Faces.setFlashAttribute(DEFAULT_ERROR_KEY_ATTRIBUTE_NAME, e);
            int loginFailedWaitTime = Faces.getRequestAttribute(LOGIN_WAITTIME_ATTR_NAME);
            if (loginFailedWaitTime != 0) {
                TimeUnit.SECONDS.sleep(loginFailedWaitTime);
            }
            redirectToView();
        }
    }

    /**
     * JSF login failure method
     */
    public static void loginFailed() {
        Faces.setFlashAttribute(DEFAULT_ERROR_KEY_ATTRIBUTE_NAME, Faces.getRequestAttribute(DEFAULT_ERROR_KEY_ATTRIBUTE_NAME));
        Faces.removeRequestAttribute(DEFAULT_ERROR_KEY_ATTRIBUTE_NAME);
        redirectToView();
    }

    public static void logout() {
        Forms.logout(Faces.getRequestAttribute(LOGOUT_PREDICATE_ATTR_NAME), "");
    }

    /**
     * Faces variant
     *
     * @param useFallback
     * @param fallbackPath
     */
    public static void logout(FallbackPredicate useFallback, String fallbackPath) {
        logout(Faces.getRequest(), Faces.getResponse(), useFallback, fallbackPath);
    }

    /**
     * makes sure that there is no double-logout
     *
     * @param request
     * @param response
     * @param useFallback
     * @param fallbackPath
     */
    public static void logout(HttpServletRequest request, HttpServletResponse response,
                              FallbackPredicate useFallback, String fallbackPath) {
        if (!Boolean.TRUE.toString().equals(request.getHeader(FORM_IS_RESUBMITTED))) {
            SecurityUtils.getSubject().logout();
            FormResubmitSupport.redirectToView(request, response, useFallback, fallbackPath);
        }
    }

    public static boolean isLoggedIn() {
        var subject = SecurityUtils.getSubject();
        return subject.isAuthenticated() || subject.isRemembered();
    }

    public static boolean isSessionExpired() {
        return wasViewExpired() || Boolean.parseBoolean(Faces.getRequestParameter(SESSION_EXPIRED_PARAMETER));
    }
}
