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
import static org.apache.shiro.ee.filters.FormResubmitSupport.SESSION_EXPIRED_PARAMETER;
import static org.apache.shiro.ee.filters.LogoutFilter.LOGOUT_PREDICATE_ATTR_NAME;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitDisabled;
import java.util.concurrent.TimeUnit;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.SneakyThrows;
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
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings("HideUtilityClassConstructor")
public class Forms {
    /**
     * Request parameter that, when present on the login request (e.g. from a checked checkbox),
     * discards the user's saved form data instead of submitting it after login
     */
    public static final String DISCARD_FORM_DATA_PARAMETER = "org.apache.shiro.form-data.discard";

    /**
     * JSF access points
     */
    @Named("authc")
    @ApplicationScoped
    @SuppressWarnings("unused")
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
         * @param username the username
         * @param password the password
         */
        public void login(String username, String password) {
            login(username, password, false);
        }

        /**
         * manual login with timeout
         *
         * @param username the username
         * @param password the password
         * @param rememberMe whether to remember the user
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
            return redirectIfLoggedIn("/");
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

        /**
         * @return true if the user has form data saved, to be submitted after login, see {@link #getDiscardFormDataParameter()}
         */
        public boolean isFormDataSaved() {
            return Forms.isFormDataSaved(Faces.getRequest());
        }

        /**
         * @return the path of the page whose form data is saved, or null
         */
        public String getSavedFormDataPath() {
            return Forms.getSavedFormDataPath(Faces.getRequest());
        }

        /**
         * @return name for a login-form checkbox that lets the user discard the saved form data,
         * see {@link Forms#DISCARD_FORM_DATA_PARAMETER}
         */
        public String getDiscardFormDataParameter() {
            return DISCARD_FORM_DATA_PARAMETER;
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
     * @param useFallbackPath whether to use fallback path
     * @param fallbackPath the fallback path to use if no saved request is found
     */
    public static void redirectToSaved(FallbackPredicate useFallbackPath, String fallbackPath) {
        FormResubmitSupport.redirectToSaved(Faces.getRequest(), Faces.getResponse(), useFallbackPath, fallbackPath,
                !isFormResubmitDisabled(Faces.getRequest().getServletContext()));
    }

    /**
     * Jakarta Faces variant
     * redirects to current view after a form submit, or a logout, for example
     */
    public static void redirectToView() {
        FormResubmitSupport.redirectToView(Faces.getRequest(), Faces.getResponse());
    }

    /**
     * Jakarta Faces variant
     * @param useFallbackPath whether to use fallback path
     * @param fallbackPath the fallback path to use if no saved request is found
     */
    public static void redirectToView(FallbackPredicate useFallbackPath, String fallbackPath) {
        FormResubmitSupport.redirectToView(Faces.getRequest(), Faces.getResponse(), useFallbackPath, fallbackPath);
    }

    /**
     * manually login, used via {@link PassThruAuthenticationFilter}
     * @param username the username
     * @param password the password
     * @param rememberMe whether to remember the user
     */
    @SneakyThrows(InterruptedException.class)
    public static void login(String username, String password, boolean rememberMe) {
        try {
            SecurityUtils.getSubject().login(new UsernamePasswordToken(username, password, rememberMe));
            redirectToSaved(Faces.getRequestAttribute(LOGIN_PREDICATE_ATTR_NAME), "/");
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

    /**
     * Jakarta Faces variant
     */
    public static void logout() {
        Forms.logout(Faces.getRequestAttribute(LOGOUT_PREDICATE_ATTR_NAME), "");
    }

    /**
     * Jakarta Faces variant
     * @param useFallback whether to use fallback path
     * @param fallbackPath the fallback path to use if no saved request is found
     */
    public static void logout(FallbackPredicate useFallback, String fallbackPath) {
        logout(Faces.getRequest(), Faces.getResponse(), useFallback, fallbackPath);
    }

    /**
     * makes sure that there is no double-logout
     *
     * @param request the HTTP servlet request
     * @param response the HTTP servlet response
     * @param useFallback whether to use fallback path
     * @param fallbackPath the fallback path to use if no saved request is found
     */
    public static void logout(HttpServletRequest request, HttpServletResponse response,
            FallbackPredicate useFallback, String fallbackPath) {
        if (SecurityUtils.getSubject().isRemembered() || !FormResubmitRequest.isResubmit(request)) {
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

    /**
     * @param request the HTTP servlet request
     * @return true if the user has form data saved, to be submitted after login
     */
    public static boolean isFormDataSaved(HttpServletRequest request) {
        return FormResubmitSupport.hasSavedFormData(request);
    }

    /**
     * @param request the HTTP servlet request
     * @return the path of the page whose form data is saved, or null
     */
    public static String getSavedFormDataPath(HttpServletRequest request) {
        return FormResubmitSupport.getSavedRequest(request);
    }
}
