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

import static org.apache.shiro.ee.cdi.ShiroScopeContext.isWebContainerSessions;
import static org.apache.shiro.ee.filters.FormResubmitSupport.getNativeSessionManager;
import java.net.HttpCookie;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.servlet.ServletContext;
import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.ee.listeners.EnvironmentLoaderListener;
import static org.apache.shiro.web.servlet.ShiroHttpSession.DEFAULT_SESSION_ID_NAME;

/**
 * Cookie Support methods
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings("HideUtilityClassConstructor")
public class FormResubmitSupportCookies {
    static final String DONT_ADD_ANY_MORE_COOKIES = "org.apache.shiro.no-more-cookies";

    static void addCookie(@NonNull HttpServletResponse response, ServletContext servletContext,
            @NonNull String cookieName, @NonNull String cookieValue, int maxAge) {
        var cookie = new Cookie(cookieName, cookieValue);
        cookie.setPath(servletContext.getContextPath());
        cookie.setMaxAge(maxAge);
        if (EnvironmentLoaderListener.isFormResubmitSecureCookies(servletContext)) {
            cookie.setSecure(true);
        }
        response.addCookie(cookie);
    }

    static void deleteCookie(@NonNull HttpServletResponse response, ServletContext servletContext,
            @NonNull String cookieName) {
        var cookieToDelete = new Cookie(cookieName, "tbd");
        cookieToDelete.setPath(servletContext.getContextPath());
        cookieToDelete.setMaxAge(0);
        if (EnvironmentLoaderListener.isFormResubmitSecureCookies(servletContext)) {
            cookieToDelete.setSecure(true);
        }
        response.addCookie(cookieToDelete);
    }

    static int getCookieAge(ServletRequest request, org.apache.shiro.mgt.SecurityManager securityManager) {
        var nativeSessionManager = getNativeSessionManager(securityManager);
        if (nativeSessionManager != null) {
            return (int) Duration.ofMillis(nativeSessionManager.getGlobalSessionTimeout()).toSeconds();
        } else {
            try {
                return (int) Duration.ofMinutes(request.getServletContext().getSessionTimeout()).toSeconds();
            } catch (NoSuchMethodError noSuchMethodError) {
                // Older servers (e.g. Jetty 9.x) do not support getSessionTimeout() at all
                log.debug("ServletContext.getSessionTimeout() not supported", noSuchMethodError);
                return (int) Duration.ofHours(1).toSeconds();
            }
        }
    }

    static String getSessionCookieName(ServletContext context, org.apache.shiro.mgt.SecurityManager securityManager) {
        if (!isWebContainerSessions(securityManager) && getNativeSessionManager(securityManager) != null) {
            return getNativeSessionManager(securityManager).getSessionIdCookie().getName();
        } else {
            return context.getSessionCookieConfig().getName() != null
                    ? context.getSessionCookieConfig().getName() : DEFAULT_SESSION_ID_NAME;
        }
    }

    static Map<String, String> transformCookieHeader(@NonNull List<String> cookies) {
        return cookieStreamFromHeader(cookies)
                .collect(Collectors.toMap(HttpCookie::getName, HttpCookie::getValue));
    }

    static Stream<HttpCookie> cookieStreamFromHeader(@NonNull List<String> cookies) {
        return cookies.stream().map(HttpCookie::parse).map(list -> list.get(0));
    }
}
