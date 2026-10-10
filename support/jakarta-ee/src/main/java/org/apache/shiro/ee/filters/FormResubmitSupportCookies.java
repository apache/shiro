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

import static org.apache.shiro.ee.filters.FormResubmitSupport.getNativeSessionManager;
import static org.apache.shiro.ee.listeners.EnvironmentLoaderListener.isFormResubmitSecureCookies;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

/**
 * Cookie Support methods
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
@SuppressWarnings("HideUtilityClassConstructor")
public class FormResubmitSupportCookies {
    private static final String HOST_PREFIX = "__Host-";

    /**
     * With secure cookies, the {@code __Host-} prefix makes browsers refuse the cookie unless this very host
     * set it over HTTPS, so it can't be planted from another subdomain or over plain HTTP.
     * The prefix requires {@code Path=/}, hence the context path moves into the name, URL-encoded
     * (cookie-name safe) to keep co-hosted applications apart.
     */
    static String cookieName(ServletContext servletContext, @NonNull String baseName) {
        return isFormResubmitSecureCookies(servletContext)
                ? HOST_PREFIX + baseName + URLEncoder.encode(servletContext.getContextPath(), StandardCharsets.UTF_8)
                : baseName;
    }

    private static Cookie newCookie(ServletContext servletContext, String baseName, String value, int maxAge,
            boolean useHostPrefix) {
        var cookie = new Cookie(useHostPrefix ? cookieName(servletContext, baseName) : baseName, value);
        boolean secure = useHostPrefix && isFormResubmitSecureCookies(servletContext);
        cookie.setPath(secure ? "/" : servletContext.getContextPath());
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAge);
        return cookie;
    }

    /**
     * @param cookieName base name, see {@link #cookieName}
     */
    static void addCookie(@NonNull HttpServletResponse response, ServletContext servletContext,
            @NonNull String cookieName, @NonNull String cookieValue, int maxAge, boolean httpOnly) {
        var cookie = newCookie(servletContext, cookieName, cookieValue, maxAge, true);
        cookie.setHttpOnly(httpOnly);
        response.addCookie(cookie);
    }

    /**
     * @param cookieName base name, see {@link #cookieName}
     * @param useHostPrefix false for a plain-name, context-scoped cookie regardless of the secure-cookie setting
     */
    static void deleteCookie(@NonNull HttpServletResponse response, ServletContext servletContext,
            @NonNull String cookieName, boolean useHostPrefix) {
        response.addCookie(newCookie(servletContext, cookieName, "tbd", 0, useHostPrefix));
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
}
